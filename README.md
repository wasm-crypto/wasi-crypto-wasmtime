# wasi-crypto-wasmtime

Glue that lets Wasmtime hand a guest the [wasi-crypto] functions the same way it
hands out the regular preview1 WASI calls.

A WebAssembly program imports `wasi_ephemeral_crypto_*` functions, the host
resolves them to a real cryptography implementation, and the guest never has to
ship a crypto library of its own.

There are three moving parts:

- **The crypto implementation.** The [`wasi-crypto`](https://crates.io/crates/wasi-crypto)
  crate (developed in the `wasi-crypto-host-functions` repository) does all the
  actual work. It exposes a
  `CryptoCtx` whose methods speak in Rust terms: `u32` handles, `&[u8]` slices,
  `&str`, and `Result<_, CryptoError>`. It knows nothing about WebAssembly.

- **The ABI.** The witx files under `witx/` describe the wasm-facing interface:
  guest pointers, lengths, and a `crypto_errno` integer for every call.

- **This crate.** It runs the witx through [Wiggle], which generates one host
  trait per witx module plus a matching `add_to_linker`. `src/lib.rs` implements
  those traits by reading arguments out of guest memory, calling the matching
  `CryptoCtx` method, and writing the results back. That's the whole bridge.

## Running the demo

```sh
# Build the guest program (a normal wasm32-wasip1 binary).
cd examples/guest && cargo build --target wasm32-wasip1 --release && cd ../..

# Run it on Wasmtime with WASI + wasi-crypto wired in.
cargo run --example run_demo
```

Expected output:

```
guest: starting, all crypto runs on the host via wasi-crypto

SHA-256("hello wasi-crypto") = d87a6d10551cbd4490084ba9d89f37db24459b46e93677a45eababa04dad85e5
Ed25519 signature (64 bytes) verified against the message
Ed25519 rejects a tampered message as expected
AES-128-GCM round trip ok: 14 bytes plaintext -> 30 bytes ciphertext -> back
X25519 agreement ok: both sides derived e434d9b3f0300c5a = e434d9b3f0300c5a

guest: all wasi-crypto operations succeeded
```

The guest (`examples/guest/src/main.rs`) drives hashing, Ed25519 signing and
verification, AES-128-GCM, and an X25519 key agreement — every one of them a
host call. The two sides of the X25519 line always match each other, but the
value itself changes on every run because the keys are generated fresh each
time.

## Using it in your own embedder

Add the crate alongside the Wasmtime release it targets. The version tracks
Wasmtime's, so `wasi-crypto-wasmtime` 45.x is built against Wasmtime 45.x:

```toml
[dependencies]
wasmtime = "45"
wasi-crypto-wasmtime = "45"
```

Then wire it into your linker the same way you wire in WASI:

```rust
use wasmtime::Linker;
use wasi_crypto_wasmtime::WasiCryptoCtx;

// `Host` is whatever you store in your `Store`; it just has to be able to
// produce a `&mut WasiCryptoCtx`.
wasi_crypto_wasmtime::add_to_linker(&mut linker, |host: &mut Host| &mut host.crypto)?;
```

`add_to_linker` registers all five witx modules (common, asymmetric-common,
signatures, symmetric, key-exchange) at once.
