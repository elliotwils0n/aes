#![allow(unused)]

mod aes;
mod dec;
mod enc;
mod key;
mod lookup;
mod mode;
mod state;

pub(crate) const NB: usize = 4;
pub(crate) const BLOCK_SIZE: usize = 16;

pub(crate) type State = [[u8; NB]; 4];
pub(crate) type Block = [u8; BLOCK_SIZE];
pub(crate) type Word = [u8; 4];

/// Different modes to use with aes block cipher encryption.
/// ECB dosen't need additional parameters but it is considered unsecured.
/// CBC requires initialization vector.
pub enum Mode<'a> {
    Ecb,
    Cbc(&'a [u8; BLOCK_SIZE]),
}

/// Encrypts data in given mode.
pub fn encrypt(plaintext: &[u8], key: &[u8], mode: Mode) -> Vec<u8> {
    match mode {
        Mode::Ecb => mode::ecb::encrypt(plaintext, key),
        Mode::Cbc(iv) => mode::cbc::encrypt(plaintext, key, iv),
    }
}

/// Decrypts data in given mode.
pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode) -> Vec<u8> {
    match mode {
        Mode::Ecb => mode::ecb::decrypt(ciphertext, key),
        Mode::Cbc(iv) => mode::cbc::decrypt(ciphertext, key, iv),
    }
}
