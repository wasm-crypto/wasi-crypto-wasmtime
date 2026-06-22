//! Glue that exposes the `wasi-crypto` host functions to Wasmtime, the same way
//! Wasmtime exposes the regular preview1 WASI calls.
//!
//! The heavy lifting (every cryptographic primitive, every handle table) lives
//! in the `wasi-crypto` host-functions crate, which speaks in terms of Rust
//! slices and `u32` handles. The wasm ABI, on the other hand, speaks in terms of
//! guest pointers and integer error codes. Wiggle bridges the two: from the
//! witx description it generates one host trait per witx module plus a matching
//! `add_to_linker`. All this file does is implement those traits by reading the
//! arguments out of guest memory, calling into the `CryptoCtx`, and writing the
//! results back.

use wasi_crypto::{
    AlgorithmType as HostAlgorithmType, CryptoCtx, CryptoError, Handle, KeyPairEncoding,
    PublicKeyEncoding, SecretKeyEncoding, SignatureEncoding, Version,
};
use wiggle::{GuestError, GuestMemory, GuestPtr};

/// Host state for the wasi-crypto functions. Drop this into your Wasmtime store
/// (or expose it through a view) and hand `add_to_linker` a closure returning
/// `&mut WasiCryptoCtx`.
pub struct WasiCryptoCtx {
    ctx: CryptoCtx,
}

impl Default for WasiCryptoCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl WasiCryptoCtx {
    pub fn new() -> Self {
        Self {
            ctx: CryptoCtx::new(),
        }
    }
}

/// Either something went wrong inside the cryptography layer (`CryptoError`) or
/// while touching guest memory (`GuestError`). Both funnel into a single witx
/// `crypto_errno` for the guest.
#[derive(Debug, thiserror::Error)]
pub enum WasiCryptoError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("guest memory error: {0}")]
    Guest(#[from] GuestError),
}

type WResult<T> = Result<T, WasiCryptoError>;

mod generated {
    use super::{WasiCryptoCtx, WasiCryptoError};
    wiggle::from_witx!({
        witx: ["witx/wasi_ephemeral_crypto.witx"],
        errors: { crypto_errno => WasiCryptoError },
    });

    impl wiggle::GuestErrorType for types::CryptoErrno {
        fn success() -> Self {
            Self::Success
        }
    }

    impl types::UserErrorConversion for WasiCryptoCtx {
        fn crypto_errno_from_wasi_crypto_error(
            &mut self,
            e: super::WasiCryptoError,
        ) -> wiggle::error::Result<types::CryptoErrno> {
            Ok(super::to_errno(e))
        }
    }
}

pub use generated::types;

/// Register the complete wasi-crypto API (all five witx modules) on a linker in
/// one call, the same way `wasmtime_wasi::p1::add_to_linker_sync` registers WASI.
pub fn add_to_linker<T: 'static>(
    linker: &mut wiggle::wasmtime_crate::Linker<T>,
    get_cx: impl Fn(&mut T) -> &mut WasiCryptoCtx + Send + Sync + Copy + 'static,
) -> wiggle::error::Result<()> {
    use generated::*;
    wasi_ephemeral_crypto_common::add_to_linker(linker, get_cx)?;
    wasi_ephemeral_crypto_asymmetric_common::add_to_linker(linker, get_cx)?;
    wasi_ephemeral_crypto_signatures::add_to_linker(linker, get_cx)?;
    wasi_ephemeral_crypto_symmetric::add_to_linker(linker, get_cx)?;
    wasi_ephemeral_crypto_kx::add_to_linker(linker, get_cx)?;
    Ok(())
}

fn to_errno(e: WasiCryptoError) -> types::CryptoErrno {
    use types::CryptoErrno as E;
    let crypto = match e {
        WasiCryptoError::Crypto(c) => c,
        // A fault while reading or writing guest memory is, from the guest's
        // point of view, an internal inconsistency.
        WasiCryptoError::Guest(_) => return E::GuestError,
    };
    match crypto {
        CryptoError::Success => E::Success,
        CryptoError::GuestError(_) => E::GuestError,
        CryptoError::NotImplemented => E::NotImplemented,
        CryptoError::UnsupportedFeature => E::UnsupportedFeature,
        CryptoError::ProhibitedOperation => E::ProhibitedOperation,
        CryptoError::UnsupportedEncoding => E::UnsupportedEncoding,
        CryptoError::UnsupportedAlgorithm => E::UnsupportedAlgorithm,
        CryptoError::UnsupportedOption => E::UnsupportedOption,
        CryptoError::InvalidKey => E::InvalidKey,
        CryptoError::InvalidLength => E::InvalidLength,
        CryptoError::VerificationFailed => E::VerificationFailed,
        CryptoError::RNGError => E::RngError,
        CryptoError::AlgorithmFailure => E::AlgorithmFailure,
        CryptoError::InvalidSignature => E::InvalidSignature,
        CryptoError::Closed => E::Closed,
        CryptoError::InvalidHandle => E::InvalidHandle,
        CryptoError::Overflow => E::Overflow,
        CryptoError::InternalError => E::InternalError,
        CryptoError::TooManyHandles => E::TooManyHandles,
        CryptoError::KeyNotSupported => E::KeyNotSupported,
        CryptoError::KeyRequired => E::KeyRequired,
        CryptoError::InvalidTag => E::InvalidTag,
        CryptoError::InvalidOperation => E::InvalidOperation,
        CryptoError::NonceRequired => E::NonceRequired,
        CryptoError::InvalidNonce => E::InvalidNonce,
        CryptoError::OptionNotSet => E::OptionNotSet,
        CryptoError::NotFound => E::NotFound,
        CryptoError::ParametersMissing => E::ParametersMissing,
        CryptoError::IncompatibleKeys => E::IncompatibleKeys,
        CryptoError::Expired => E::Expired,
    }
}

// --- guest-memory helpers ---------------------------------------------------

/// Read a `(pointer, len)` pair out of guest memory into an owned buffer. We
/// copy eagerly so the immutable borrow of guest memory is released before we
/// need to write any output back.
fn read_bytes(mem: &GuestMemory<'_>, ptr: GuestPtr<u8>, len: types::Size) -> WResult<Vec<u8>> {
    Ok(mem.as_cow(ptr.as_array(len))?.into_owned())
}

/// Read a guest string into an owned `String`.
fn read_str(mem: &GuestMemory<'_>, ptr: GuestPtr<str>) -> WResult<String> {
    Ok(mem.as_cow_str(ptr)?.into_owned())
}

/// Copy `data` into a guest `(pointer, max_len)` buffer, returning the number of
/// bytes written. Mirrors the host contract: the guest buffer may be larger than
/// the data, but never smaller.
fn write_bytes(
    mem: &mut GuestMemory<'_>,
    ptr: GuestPtr<u8>,
    max_len: types::Size,
    data: &[u8],
) -> WResult<types::Size> {
    if data.len() > max_len as usize {
        return Err(CryptoError::Overflow.into());
    }
    mem.copy_from_slice(data, ptr.as_array(data.len() as u32))?;
    Ok(data.len() as types::Size)
}

/// Run a host operation that fills a guest `(pointer, len)` output buffer and
/// reports how many bytes it wrote. On ordinary (unshared) memory the host
/// writes straight into the guest's buffer; for shared memory — where we can't
/// hand out a `&mut` view — we stage in a scratch buffer and copy. Either way the
/// host's own bounds checks against the `len`-sized buffer apply.
fn fill_out_buf(
    mem: &mut GuestMemory<'_>,
    ptr: GuestPtr<u8>,
    len: types::Size,
    fill: impl FnOnce(&mut [u8]) -> Result<usize, CryptoError>,
) -> WResult<types::Size> {
    if let Some(dst) = mem.as_slice_mut(ptr.as_array(len))? {
        let n = fill(dst)?;
        return Ok(n as types::Size);
    }
    let mut tmp = vec![0u8; len as usize];
    let n = fill(&mut tmp)?;
    write_bytes(mem, ptr, len, &tmp[..n])
}

// --- enum conversions -------------------------------------------------------

impl From<types::AlgorithmType> for HostAlgorithmType {
    fn from(a: types::AlgorithmType) -> Self {
        match a {
            types::AlgorithmType::Signatures => HostAlgorithmType::Signatures,
            types::AlgorithmType::Symmetric => HostAlgorithmType::Symmetric,
            types::AlgorithmType::KeyExchange => HostAlgorithmType::KeyExchange,
        }
    }
}

impl From<types::KeypairEncoding> for KeyPairEncoding {
    fn from(e: types::KeypairEncoding) -> Self {
        match e {
            types::KeypairEncoding::Raw => KeyPairEncoding::Raw,
            types::KeypairEncoding::Pkcs8 => KeyPairEncoding::Pkcs8,
            types::KeypairEncoding::Pem => KeyPairEncoding::Pem,
            types::KeypairEncoding::Local => KeyPairEncoding::Local,
        }
    }
}

impl From<types::PublickeyEncoding> for PublicKeyEncoding {
    fn from(e: types::PublickeyEncoding) -> Self {
        match e {
            types::PublickeyEncoding::Raw => PublicKeyEncoding::Raw,
            types::PublickeyEncoding::Pkcs8 => PublicKeyEncoding::Pkcs8,
            types::PublickeyEncoding::Pem => PublicKeyEncoding::Pem,
            types::PublickeyEncoding::Sec => PublicKeyEncoding::Sec,
            types::PublickeyEncoding::Local => PublicKeyEncoding::Local,
        }
    }
}

impl From<types::SecretkeyEncoding> for SecretKeyEncoding {
    fn from(e: types::SecretkeyEncoding) -> Self {
        match e {
            types::SecretkeyEncoding::Raw => SecretKeyEncoding::Raw,
            types::SecretkeyEncoding::Pkcs8 => SecretKeyEncoding::Pkcs8,
            types::SecretkeyEncoding::Pem => SecretKeyEncoding::Pem,
            types::SecretkeyEncoding::Sec => SecretKeyEncoding::Sec,
            types::SecretkeyEncoding::Local => SecretKeyEncoding::Local,
        }
    }
}

impl From<types::SignatureEncoding> for SignatureEncoding {
    fn from(e: types::SignatureEncoding) -> Self {
        match e {
            types::SignatureEncoding::Raw => SignatureEncoding::Raw,
            types::SignatureEncoding::Der => SignatureEncoding::Der,
        }
    }
}

fn opt_options(o: &types::OptOptions) -> Option<Handle> {
    match o {
        types::OptOptions::Some(h) => Some((*h).into()),
        types::OptOptions::None => None,
    }
}

fn opt_symmetric_key(o: &types::OptSymmetricKey) -> Option<Handle> {
    match o {
        types::OptSymmetricKey::Some(h) => Some((*h).into()),
        types::OptSymmetricKey::None => None,
    }
}

// --- common -----------------------------------------------------------------

impl generated::wasi_ephemeral_crypto_common::WasiEphemeralCryptoCommon for WasiCryptoCtx {
    fn options_open(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        algorithm_type: types::AlgorithmType,
    ) -> WResult<types::Options> {
        Ok(self.ctx.options_open(algorithm_type.into())?.into())
    }

    fn options_close(&mut self, _mem: &mut GuestMemory<'_>, handle: types::Options) -> WResult<()> {
        Ok(self.ctx.options_close(handle.into())?)
    }

    fn options_set(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::Options,
        name: GuestPtr<str>,
        value: GuestPtr<u8>,
        value_len: types::Size,
    ) -> WResult<()> {
        let name = read_str(mem, name)?;
        let value = read_bytes(mem, value, value_len)?;
        Ok(self.ctx.options_set(handle.into(), &name, &value)?)
    }

    fn options_set_u64(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::Options,
        name: GuestPtr<str>,
        value: u64,
    ) -> WResult<()> {
        let name = read_str(mem, name)?;
        Ok(self.ctx.options_set_u64(handle.into(), &name, value)?)
    }

    fn options_set_guest_buffer(
        &mut self,
        mem: &mut GuestMemory<'_>,
        _handle: types::Options,
        name: GuestPtr<str>,
        _buffer: GuestPtr<u8>,
        _buffer_len: types::Size,
    ) -> WResult<()> {
        // The guest-buffer fast-path lets memory-hard functions scribble their
        // scratch space straight into guest memory. It needs a `'static mut`
        // view of guest memory, which can't be produced soundly under Wiggle's
        // borrow model (the memory may grow and move). None of the algorithms
        // implemented by the host actually read this buffer back, so accepting
        // the option without storing it is behaviourally equivalent here.
        let _ = read_str(mem, name)?;
        Ok(())
    }

    fn array_output_len(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        array_output: types::ArrayOutput,
    ) -> WResult<types::Size> {
        Ok(self.ctx.array_output_len(array_output.into())? as types::Size)
    }

    fn array_output_pull(
        &mut self,
        mem: &mut GuestMemory<'_>,
        array_output: types::ArrayOutput,
        buf: GuestPtr<u8>,
        buf_len: types::Size,
    ) -> WResult<types::Size> {
        fill_out_buf(mem, buf, buf_len, |out| {
            self.ctx.array_output_pull(array_output.into(), out)
        })
    }

    fn secrets_manager_open(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        options: &types::OptOptions,
    ) -> WResult<types::SecretsManager> {
        Ok(self.ctx.secrets_manager_open(opt_options(options))?.into())
    }

    fn secrets_manager_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
    ) -> WResult<()> {
        Ok(self.ctx.secrets_manager_close(secrets_manager.into())?)
    }

    fn secrets_manager_invalidate(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        key_id: GuestPtr<u8>,
        key_id_len: types::Size,
        key_version: types::Version,
    ) -> WResult<()> {
        let key_id = read_bytes(mem, key_id, key_id_len)?;
        Ok(self.ctx.secrets_manager_invalidate(
            secrets_manager.into(),
            &key_id,
            Version(key_version),
        )?)
    }
}

// --- asymmetric_common ------------------------------------------------------

impl generated::wasi_ephemeral_crypto_asymmetric_common::WasiEphemeralCryptoAsymmetricCommon
    for WasiCryptoCtx
{
    fn keypair_generate(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm_type: types::AlgorithmType,
        algorithm: GuestPtr<str>,
        options: &types::OptOptions,
    ) -> WResult<types::Keypair> {
        let alg = read_str(mem, algorithm)?;
        Ok(self
            .ctx
            .keypair_generate(algorithm_type.into(), &alg, opt_options(options))?
            .into())
    }

    fn keypair_import(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm_type: types::AlgorithmType,
        algorithm: GuestPtr<str>,
        encoded: GuestPtr<u8>,
        encoded_len: types::Size,
        encoding: types::KeypairEncoding,
    ) -> WResult<types::Keypair> {
        let alg = read_str(mem, algorithm)?;
        let encoded = read_bytes(mem, encoded, encoded_len)?;
        Ok(self
            .ctx
            .keypair_import(algorithm_type.into(), &alg, &encoded, encoding.into())?
            .into())
    }

    fn keypair_generate_managed(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        algorithm_type: types::AlgorithmType,
        algorithm: GuestPtr<str>,
        options: &types::OptOptions,
    ) -> WResult<types::Keypair> {
        let alg = read_str(mem, algorithm)?;
        Ok(self
            .ctx
            .keypair_generate_managed(
                secrets_manager.into(),
                algorithm_type.into(),
                &alg,
                opt_options(options),
            )?
            .into())
    }

    fn keypair_store_managed(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        kp: types::Keypair,
        kp_id: GuestPtr<u8>,
        kp_id_max_len: types::Size,
    ) -> WResult<()> {
        let mut tmp = vec![0u8; kp_id_max_len as usize];
        self.ctx
            .keypair_store_managed(secrets_manager.into(), kp.into(), &mut tmp)?;
        write_bytes(mem, kp_id, kp_id_max_len, &tmp)?;
        Ok(())
    }

    fn keypair_replace_managed(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        kp_old: types::Keypair,
        kp_new: types::Keypair,
    ) -> WResult<types::Version> {
        Ok(self
            .ctx
            .keypair_replace_managed(secrets_manager.into(), kp_old.into(), kp_new.into())?
            .0)
    }

    fn keypair_id(
        &mut self,
        mem: &mut GuestMemory<'_>,
        kp: types::Keypair,
        kp_id: GuestPtr<u8>,
        kp_id_max_len: types::Size,
    ) -> WResult<(types::Size, types::Version)> {
        let (id, version) = self.ctx.keypair_id(kp.into())?;
        let n = write_bytes(mem, kp_id, kp_id_max_len, &id)?;
        Ok((n, version.0))
    }

    fn keypair_from_id(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        kp_id: GuestPtr<u8>,
        kp_id_len: types::Size,
        kp_version: types::Version,
    ) -> WResult<types::Keypair> {
        let kp_id = read_bytes(mem, kp_id, kp_id_len)?;
        Ok(self
            .ctx
            .keypair_from_id(secrets_manager.into(), &kp_id, Version(kp_version))?
            .into())
    }

    fn keypair_from_pk_and_sk(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        publickey: types::Publickey,
        secretkey: types::Secretkey,
    ) -> WResult<types::Keypair> {
        Ok(self
            .ctx
            .keypair_from_pk_and_sk(publickey.into(), secretkey.into())?
            .into())
    }

    fn keypair_export(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        kp: types::Keypair,
        encoding: types::KeypairEncoding,
    ) -> WResult<types::ArrayOutput> {
        Ok(self.ctx.keypair_export(kp.into(), encoding.into())?.into())
    }

    fn keypair_publickey(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        kp: types::Keypair,
    ) -> WResult<types::Publickey> {
        Ok(self.ctx.keypair_publickey(kp.into())?.into())
    }

    fn keypair_secretkey(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        kp: types::Keypair,
    ) -> WResult<types::Secretkey> {
        Ok(self.ctx.keypair_secretkey(kp.into())?.into())
    }

    fn keypair_close(&mut self, _mem: &mut GuestMemory<'_>, kp: types::Keypair) -> WResult<()> {
        Ok(self.ctx.keypair_close(kp.into())?)
    }

    fn publickey_import(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm_type: types::AlgorithmType,
        algorithm: GuestPtr<str>,
        encoded: GuestPtr<u8>,
        encoded_len: types::Size,
        encoding: types::PublickeyEncoding,
    ) -> WResult<types::Publickey> {
        let alg = read_str(mem, algorithm)?;
        let encoded = read_bytes(mem, encoded, encoded_len)?;
        Ok(self
            .ctx
            .publickey_import(algorithm_type.into(), &alg, &encoded, encoding.into())?
            .into())
    }

    fn publickey_export(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        pk: types::Publickey,
        encoding: types::PublickeyEncoding,
    ) -> WResult<types::ArrayOutput> {
        Ok(self
            .ctx
            .publickey_export(pk.into(), encoding.into())?
            .into())
    }

    fn publickey_verify(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        pk: types::Publickey,
    ) -> WResult<()> {
        Ok(self.ctx.publickey_verify(pk.into())?)
    }

    fn publickey_from_secretkey(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        sk: types::Secretkey,
    ) -> WResult<types::Publickey> {
        Ok(self.ctx.publickey(sk.into())?.into())
    }

    fn publickey_close(&mut self, _mem: &mut GuestMemory<'_>, pk: types::Publickey) -> WResult<()> {
        Ok(self.ctx.publickey_close(pk.into())?)
    }

    fn secretkey_import(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm_type: types::AlgorithmType,
        algorithm: GuestPtr<str>,
        encoded: GuestPtr<u8>,
        encoded_len: types::Size,
        encoding: types::SecretkeyEncoding,
    ) -> WResult<types::Secretkey> {
        let alg = read_str(mem, algorithm)?;
        let encoded = read_bytes(mem, encoded, encoded_len)?;
        Ok(self
            .ctx
            .secretkey_import(algorithm_type.into(), &alg, &encoded, encoding.into())?
            .into())
    }

    fn secretkey_export(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        sk: types::Secretkey,
        encoding: types::SecretkeyEncoding,
    ) -> WResult<types::ArrayOutput> {
        Ok(self
            .ctx
            .secretkey_export(sk.into(), encoding.into())?
            .into())
    }

    fn secretkey_close(&mut self, _mem: &mut GuestMemory<'_>, sk: types::Secretkey) -> WResult<()> {
        Ok(self.ctx.secretkey_close(sk.into())?)
    }
}

// --- signatures -------------------------------------------------------------

impl generated::wasi_ephemeral_crypto_signatures::WasiEphemeralCryptoSignatures for WasiCryptoCtx {
    fn signature_export(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        signature: types::Signature,
        encoding: types::SignatureEncoding,
    ) -> WResult<types::ArrayOutput> {
        Ok(self
            .ctx
            .signature_export(signature.into(), encoding.into())?
            .into())
    }

    fn signature_import(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm: GuestPtr<str>,
        encoded: GuestPtr<u8>,
        encoded_len: types::Size,
        encoding: types::SignatureEncoding,
    ) -> WResult<types::Signature> {
        let alg = read_str(mem, algorithm)?;
        let encoded = read_bytes(mem, encoded, encoded_len)?;
        Ok(self
            .ctx
            .signature_import(&alg, &encoded, encoding.into())?
            .into())
    }

    fn signature_state_open(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        kp: types::SignatureKeypair,
    ) -> WResult<types::SignatureState> {
        Ok(self.ctx.signature_state_open(kp.into())?.into())
    }

    fn signature_state_update(
        &mut self,
        mem: &mut GuestMemory<'_>,
        state: types::SignatureState,
        input: GuestPtr<u8>,
        input_len: types::Size,
    ) -> WResult<()> {
        let input = read_bytes(mem, input, input_len)?;
        Ok(self.ctx.signature_state_update(state.into(), &input)?)
    }

    fn signature_state_sign(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        state: types::SignatureState,
    ) -> WResult<types::ArrayOutput> {
        Ok(self.ctx.signature_state_sign(state.into())?.into())
    }

    fn signature_state_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        state: types::SignatureState,
    ) -> WResult<()> {
        Ok(self.ctx.signature_state_close(state.into())?)
    }

    fn signature_verification_state_open(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        kp: types::SignaturePublickey,
    ) -> WResult<types::SignatureVerificationState> {
        Ok(self
            .ctx
            .signature_verification_state_open(kp.into())?
            .into())
    }

    fn signature_verification_state_update(
        &mut self,
        mem: &mut GuestMemory<'_>,
        state: types::SignatureVerificationState,
        input: GuestPtr<u8>,
        input_len: types::Size,
    ) -> WResult<()> {
        let input = read_bytes(mem, input, input_len)?;
        Ok(self
            .ctx
            .signature_verification_state_update(state.into(), &input)?)
    }

    fn signature_verification_state_verify(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        state: types::SignatureVerificationState,
        signature: types::Signature,
    ) -> WResult<()> {
        Ok(self
            .ctx
            .signature_verification_state_verify(state.into(), signature.into())?)
    }

    fn signature_verification_state_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        state: types::SignatureVerificationState,
    ) -> WResult<()> {
        Ok(self.ctx.signature_verification_state_close(state.into())?)
    }

    fn signature_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        signature: types::Signature,
    ) -> WResult<()> {
        Ok(self.ctx.signature_close(signature.into())?)
    }
}

// --- key exchange -----------------------------------------------------------

impl generated::wasi_ephemeral_crypto_kx::WasiEphemeralCryptoKx for WasiCryptoCtx {
    fn kx_dh(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        pk: types::Publickey,
        sk: types::Secretkey,
    ) -> WResult<types::ArrayOutput> {
        Ok(self.ctx.kx_dh(pk.into(), sk.into())?.into())
    }

    fn kx_encapsulate(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        pk: types::Publickey,
    ) -> WResult<(types::ArrayOutput, types::ArrayOutput)> {
        let (secret, encapsulated) = self.ctx.kx_encapsulate(pk.into())?;
        Ok((secret.into(), encapsulated.into()))
    }

    fn kx_decapsulate(
        &mut self,
        mem: &mut GuestMemory<'_>,
        sk: types::Secretkey,
        encapsulated_secret: GuestPtr<u8>,
        encapsulated_secret_len: types::Size,
    ) -> WResult<types::ArrayOutput> {
        let encapsulated = read_bytes(mem, encapsulated_secret, encapsulated_secret_len)?;
        Ok(self.ctx.kx_decapsulate(sk.into(), &encapsulated)?.into())
    }
}

// --- symmetric --------------------------------------------------------------

impl generated::wasi_ephemeral_crypto_symmetric::WasiEphemeralCryptoSymmetric for WasiCryptoCtx {
    fn symmetric_key_generate(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm: GuestPtr<str>,
        options: &types::OptOptions,
    ) -> WResult<types::SymmetricKey> {
        let alg = read_str(mem, algorithm)?;
        Ok(self
            .ctx
            .symmetric_key_generate(&alg, opt_options(options))?
            .into())
    }

    fn symmetric_key_import(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm: GuestPtr<str>,
        raw: GuestPtr<u8>,
        raw_len: types::Size,
    ) -> WResult<types::SymmetricKey> {
        let alg = read_str(mem, algorithm)?;
        let raw = read_bytes(mem, raw, raw_len)?;
        Ok(self.ctx.symmetric_key_import(&alg, &raw)?.into())
    }

    fn symmetric_key_export(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        symmetric_key: types::SymmetricKey,
    ) -> WResult<types::ArrayOutput> {
        Ok(self.ctx.symmetric_key_export(symmetric_key.into())?.into())
    }

    fn symmetric_key_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        symmetric_key: types::SymmetricKey,
    ) -> WResult<()> {
        Ok(self.ctx.symmetric_key_close(symmetric_key.into())?)
    }

    fn symmetric_key_generate_managed(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        algorithm: GuestPtr<str>,
        options: &types::OptOptions,
    ) -> WResult<types::SymmetricKey> {
        let alg = read_str(mem, algorithm)?;
        Ok(self
            .ctx
            .symmetric_key_generate_managed(secrets_manager.into(), &alg, opt_options(options))?
            .into())
    }

    fn symmetric_key_store_managed(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        symmetric_key: types::SymmetricKey,
        symmetric_key_id: GuestPtr<u8>,
        symmetric_key_id_max_len: types::Size,
    ) -> WResult<()> {
        let mut tmp = vec![0u8; symmetric_key_id_max_len as usize];
        self.ctx.symmetric_key_store_managed(
            secrets_manager.into(),
            symmetric_key.into(),
            &mut tmp,
        )?;
        write_bytes(mem, symmetric_key_id, symmetric_key_id_max_len, &tmp)?;
        Ok(())
    }

    fn symmetric_key_replace_managed(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        symmetric_key_old: types::SymmetricKey,
        symmetric_key_new: types::SymmetricKey,
    ) -> WResult<types::Version> {
        Ok(self
            .ctx
            .symmetric_key_replace_managed(
                secrets_manager.into(),
                symmetric_key_old.into(),
                symmetric_key_new.into(),
            )?
            .0)
    }

    fn symmetric_key_id(
        &mut self,
        mem: &mut GuestMemory<'_>,
        symmetric_key: types::SymmetricKey,
        symmetric_key_id: GuestPtr<u8>,
        symmetric_key_id_max_len: types::Size,
    ) -> WResult<(types::Size, types::Version)> {
        let (id, version) = self.ctx.symmetric_key_id(symmetric_key.into())?;
        let n = write_bytes(mem, symmetric_key_id, symmetric_key_id_max_len, &id)?;
        Ok((n, version.0))
    }

    fn symmetric_key_from_id(
        &mut self,
        mem: &mut GuestMemory<'_>,
        secrets_manager: types::SecretsManager,
        symmetric_key_id: GuestPtr<u8>,
        symmetric_key_id_len: types::Size,
        symmetric_key_version: types::Version,
    ) -> WResult<types::SymmetricKey> {
        let id = read_bytes(mem, symmetric_key_id, symmetric_key_id_len)?;
        Ok(self
            .ctx
            .symmetric_key_from_id(secrets_manager.into(), &id, Version(symmetric_key_version))?
            .into())
    }

    fn symmetric_state_open(
        &mut self,
        mem: &mut GuestMemory<'_>,
        algorithm: GuestPtr<str>,
        key: &types::OptSymmetricKey,
        options: &types::OptOptions,
    ) -> WResult<types::SymmetricState> {
        let alg = read_str(mem, algorithm)?;
        Ok(self
            .ctx
            .symmetric_state_open(&alg, opt_symmetric_key(key), opt_options(options))?
            .into())
    }

    fn symmetric_state_options_get(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        name: GuestPtr<str>,
        value: GuestPtr<u8>,
        value_max_len: types::Size,
    ) -> WResult<types::Size> {
        let name = read_str(mem, name)?;
        fill_out_buf(mem, value, value_max_len, |out| {
            self.ctx
                .symmetric_state_options_get(handle.into(), &name, out)
        })
    }

    fn symmetric_state_options_get_u64(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        name: GuestPtr<str>,
    ) -> WResult<u64> {
        let name = read_str(mem, name)?;
        Ok(self
            .ctx
            .symmetric_state_options_get_u64(handle.into(), &name)?)
    }

    fn symmetric_state_clone(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
    ) -> WResult<types::SymmetricState> {
        Ok(self.ctx.symmetric_state_clone(handle.into())?.into())
    }

    fn symmetric_state_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
    ) -> WResult<()> {
        Ok(self.ctx.symmetric_state_close(handle.into())?)
    }

    fn symmetric_state_absorb(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        data: GuestPtr<u8>,
        data_len: types::Size,
    ) -> WResult<()> {
        let data = read_bytes(mem, data, data_len)?;
        Ok(self.ctx.symmetric_state_absorb(handle.into(), &data)?)
    }

    fn symmetric_state_squeeze(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        out: GuestPtr<u8>,
        out_len: types::Size,
    ) -> WResult<()> {
        let mut tmp = vec![0u8; out_len as usize];
        self.ctx.symmetric_state_squeeze(handle.into(), &mut tmp)?;
        write_bytes(mem, out, out_len, &tmp)?;
        Ok(())
    }

    fn symmetric_state_squeeze_tag(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
    ) -> WResult<types::SymmetricTag> {
        Ok(self.ctx.symmetric_state_squeeze_tag(handle.into())?.into())
    }

    fn symmetric_state_squeeze_key(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        alg_str: GuestPtr<str>,
    ) -> WResult<types::SymmetricKey> {
        let alg = read_str(mem, alg_str)?;
        Ok(self
            .ctx
            .symmetric_state_squeeze_key(handle.into(), &alg)?
            .into())
    }

    fn symmetric_state_max_tag_len(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
    ) -> WResult<types::Size> {
        Ok(self.ctx.symmetric_state_max_tag_len(handle.into())? as types::Size)
    }

    fn symmetric_state_encrypt(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        out: GuestPtr<u8>,
        out_len: types::Size,
        data: GuestPtr<u8>,
        data_len: types::Size,
    ) -> WResult<types::Size> {
        let data = read_bytes(mem, data, data_len)?;
        fill_out_buf(mem, out, out_len, |buf| {
            self.ctx.symmetric_state_encrypt(handle.into(), buf, &data)
        })
    }

    fn symmetric_state_encrypt_detached(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        out: GuestPtr<u8>,
        out_len: types::Size,
        data: GuestPtr<u8>,
        data_len: types::Size,
    ) -> WResult<types::SymmetricTag> {
        let data = read_bytes(mem, data, data_len)?;
        let mut tmp = vec![0u8; out_len as usize];
        let tag = self
            .ctx
            .symmetric_state_encrypt_detached(handle.into(), &mut tmp, &data)?;
        write_bytes(mem, out, out_len, &tmp)?;
        Ok(tag.into())
    }

    fn symmetric_state_decrypt(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        out: GuestPtr<u8>,
        out_len: types::Size,
        data: GuestPtr<u8>,
        data_len: types::Size,
    ) -> WResult<types::Size> {
        let data = read_bytes(mem, data, data_len)?;
        fill_out_buf(mem, out, out_len, |buf| {
            self.ctx.symmetric_state_decrypt(handle.into(), buf, &data)
        })
    }

    fn symmetric_state_decrypt_detached(
        &mut self,
        mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
        out: GuestPtr<u8>,
        out_len: types::Size,
        data: GuestPtr<u8>,
        data_len: types::Size,
        raw_tag: GuestPtr<u8>,
        raw_tag_len: types::Size,
    ) -> WResult<types::Size> {
        let data = read_bytes(mem, data, data_len)?;
        let raw_tag = read_bytes(mem, raw_tag, raw_tag_len)?;
        fill_out_buf(mem, out, out_len, |buf| {
            self.ctx
                .symmetric_state_decrypt_detached(handle.into(), buf, &data, &raw_tag)
        })
    }

    fn symmetric_state_ratchet(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        handle: types::SymmetricState,
    ) -> WResult<()> {
        Ok(self.ctx.symmetric_state_ratchet(handle.into())?)
    }

    fn symmetric_tag_len(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        symmetric_tag: types::SymmetricTag,
    ) -> WResult<types::Size> {
        Ok(self.ctx.symmetric_tag_len(symmetric_tag.into())? as types::Size)
    }

    fn symmetric_tag_pull(
        &mut self,
        mem: &mut GuestMemory<'_>,
        symmetric_tag: types::SymmetricTag,
        buf: GuestPtr<u8>,
        buf_len: types::Size,
    ) -> WResult<types::Size> {
        fill_out_buf(mem, buf, buf_len, |out| {
            self.ctx.symmetric_tag_pull(symmetric_tag.into(), out)
        })
    }

    fn symmetric_tag_verify(
        &mut self,
        mem: &mut GuestMemory<'_>,
        symmetric_tag: types::SymmetricTag,
        expected_raw_tag_ptr: GuestPtr<u8>,
        expected_raw_tag_len: types::Size,
    ) -> WResult<()> {
        let expected = read_bytes(mem, expected_raw_tag_ptr, expected_raw_tag_len)?;
        Ok(self
            .ctx
            .symmetric_tag_verify(symmetric_tag.into(), &expected)?)
    }

    fn symmetric_tag_close(
        &mut self,
        _mem: &mut GuestMemory<'_>,
        symmetric_tag: types::SymmetricTag,
    ) -> WResult<()> {
        Ok(self.ctx.symmetric_tag_close(symmetric_tag.into())?)
    }
}
