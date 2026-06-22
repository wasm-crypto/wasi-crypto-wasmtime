//! A small WebAssembly program that does real cryptography entirely through the
//! host. It never links a crypto library of its own — every primitive below is
//! a wasi-crypto import that Wasmtime resolves to the host implementation.

use wasi_crypto_guest::prelude::*;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

fn main() {
    println!("guest: starting, all crypto runs on the host via wasi-crypto\n");

    // 1. Hashing.
    let digest = Hash::hash("SHA-256", b"hello wasi-crypto", 32, None).expect("sha-256");
    println!("SHA-256(\"hello wasi-crypto\") = {}", hex(&digest));
    assert_eq!(digest.len(), 32);

    // 2. Ed25519 signatures.
    let kp = SignatureKeyPair::generate("Ed25519").expect("ed25519 keygen");
    let msg = b"sign me with a host-held key";
    let signature = kp.sign(msg).expect("sign");
    let pk = kp.publickey().expect("public key");
    pk.signature_verify(msg, &signature).expect("verify");
    println!(
        "Ed25519 signature ({} bytes) verified against the message",
        signature.raw().expect("raw sig").len()
    );
    // A tampered message must fail to verify.
    assert!(pk.signature_verify(b"a different message", &signature).is_err());
    println!("Ed25519 rejects a tampered message as expected");

    // 3. Authenticated encryption (AES-128-GCM).
    let key = AeadKey::generate("AES-128-GCM").expect("aead keygen");
    let nonce = [0u8; 12];
    let plaintext = b"attack at dawn";
    let mut sealing = Aead::new(&key, Some(&nonce), Some(b"context")).expect("aead seal ctx");
    let ciphertext = sealing.encrypt(plaintext).expect("encrypt");
    let mut opening = Aead::new(&key, Some(&nonce), Some(b"context")).expect("aead open ctx");
    let recovered = opening.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(recovered, plaintext);
    println!(
        "AES-128-GCM round trip ok: {} bytes plaintext -> {} bytes ciphertext -> back",
        plaintext.len(),
        ciphertext.len()
    );

    // 4. X25519 Diffie-Hellman: two parties derive the same shared secret.
    let alice = KxKeyPair::generate("X25519").expect("alice keygen");
    let bob = KxKeyPair::generate("X25519").expect("bob keygen");
    let alice_shared = alice
        .publickey()
        .unwrap()
        .dh(&bob.secretkey().unwrap())
        .expect("alice dh");
    let bob_shared = bob
        .publickey()
        .unwrap()
        .dh(&alice.secretkey().unwrap())
        .expect("bob dh");
    assert_eq!(alice_shared, bob_shared);
    println!(
        "X25519 agreement ok: both sides derived {} = {}",
        hex(&alice_shared[..8]),
        hex(&bob_shared[..8])
    );

    println!("\nguest: all wasi-crypto operations succeeded");
}
