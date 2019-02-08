mod utils;

use arrayvec::ArrayVec;
use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

/// Generate a 32-byte curve25519 key, given a 32-byte curve25519 secret key
/// and a 32-byte curve22519 public key.
///
/// If the public argument is the predefined basepoint value (9 followed by all
/// zeros), then this function will calculate a curve25519 public key.
#[wasm_bindgen]
pub fn curve25519(secret: &[u8], public: &[u8]) -> Vec<u8> {
    let sk: ArrayVec<[u8; 32]> = secret.iter().cloned().take(32).collect();
    let sk = sk.into_inner().unwrap_or_else(|_| {
        panic!("secret key must be a 32 bit array lenght.")
    });
    let pk: ArrayVec<[u8; 32]> = public.iter().cloned().take(32).collect();
    let pk = pk.into_inner().unwrap_or_else(|_| {
        panic!("public key must be a 32 bit array lenght.")
    });
    curve25519::curve25519(sk, pk).to_vec()
}

/// Generate a 32-byte curve25519 secret key.
/// from a random 32-byte value, that is used as the base
#[wasm_bindgen]
pub fn curve25519_sk(rand: &[u8]) -> Vec<u8> {
    let random_bytes: ArrayVec<[u8; 32]> =
        rand.iter().cloned().take(32).collect();
    let random_bytes = random_bytes.into_inner().unwrap_or_else(|_| {
        panic!("random bytes must be a 32 bit array lenght.")
    });

    if let Ok(sk) = curve25519::curve25519_sk(Some(random_bytes)) {
        return sk.to_vec();
    } else {
        // ok here i'm abort, which is the behavior of `unwrap()`
        // but without a lot of generated code
        std::process::abort()
    }
}

/// Generate a 32-byte curve25519 public key.
///
/// Calls curve25519 with the public key set to the basepoint value of 9
/// followed by all zeros.
#[wasm_bindgen]
pub fn curve25519_pk(secret_key: &[u8]) -> Vec<u8> {
    let sk: ArrayVec<[u8; 32]> = secret_key.iter().cloned().take(32).collect();
    let sk = sk.into_inner().unwrap_or_else(|_| {
        panic!("secret key must be a 32 bit array lenght.")
    });
    curve25519::curve25519_pk(sk).to_vec()
}
