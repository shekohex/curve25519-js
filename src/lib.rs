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

#[wasm_bindgen]
pub fn curve25519(secret: &[u8], public: &[u8]) -> Vec<u8> {
    let sk: ArrayVec<[u8; 32]> = secret.iter().cloned().take(32).collect();
    let sk = sk
        .into_inner()
        .unwrap_or_else(|_| panic!("secret key must be a 32 bit array lenght."));
    let pk: ArrayVec<[u8; 32]> = public.iter().cloned().take(32).collect();
    let pk = pk
        .into_inner()
        .unwrap_or_else(|_| panic!("public key must be a 32 bit array lenght."));
    curve25519::curve25519(sk, pk).to_vec()
}

#[wasm_bindgen]
pub fn curve25519_sk(rand: &[u8]) -> Vec<u8> {
    let random_bytes: ArrayVec<[u8; 32]> =
        rand.iter().cloned().take(32).collect();
    let random_bytes = random_bytes
        .into_inner()
        .unwrap_or_else(|_| panic!("random bytes must be a 32 bit array lenght."));
    curve25519::curve25519_sk(Some(random_bytes))
        .unwrap()
        .to_vec() // unwrap here is safe, since we sure that we give it a random bytes
}

#[wasm_bindgen]
pub fn curve25519_pk(secret_key: &[u8]) -> Vec<u8> {
    let sk: ArrayVec<[u8; 32]> = secret_key.iter().cloned().take(32).collect();
    let sk = sk
        .into_inner()
        .unwrap_or_else(|_| panic!("secret key must be a 32 bit array lenght."));
    curve25519::curve25519_pk(sk).to_vec()
}
