use std::iter::zip;

use crate::{aes, Block, BLOCK_SIZE};

pub(crate) fn encrypt(plaintext: &[u8], key: &[u8], iv: &Block) -> (Vec<u8>, Block) {
    assert_eq!(
        0,
        plaintext.len() % BLOCK_SIZE,
        "Input length is not a multiply of block size."
    );

    let mut output = Vec::<u8>::with_capacity(plaintext.len());

    let first_block: &Block = &plaintext[0..BLOCK_SIZE].try_into().unwrap();
    let mut c = aes::encrypt_block(&xor_blocks(first_block, iv), key);
    output.extend(&c);

    for i in 1..(plaintext.len() / BLOCK_SIZE) {
        let block: &Block = &plaintext[(i * BLOCK_SIZE)..((i + 1) * BLOCK_SIZE)]
            .try_into()
            .unwrap();
        let encrypted_block = aes::encrypt_block(&xor_blocks(block, &c), key);
        output.extend(encrypted_block);
        c = encrypted_block;
    }
    (output, c)
}

pub(crate) fn decrypt(ciphertext: &[u8], key: &[u8], iv: &Block) -> (Vec<u8>, Block) {
    assert_eq!(
        0,
        ciphertext.len() % BLOCK_SIZE,
        "Input length is not a multiply of block size."
    );

    let mut output = Vec::<u8>::with_capacity(ciphertext.len());

    let first_block: &Block = &ciphertext[0..BLOCK_SIZE].try_into().unwrap();
    let decrypted_first_block = aes::decrypt_block(first_block, key);
    output.extend(xor_blocks(&decrypted_first_block, iv));

    let mut c: Block = *iv;
    for i in 1..(ciphertext.len() / BLOCK_SIZE) {
        let prev_block: &Block = &ciphertext[((i - 1) * BLOCK_SIZE)..(i * BLOCK_SIZE)]
            .try_into()
            .unwrap();
        let block: &Block = &ciphertext[(i * BLOCK_SIZE)..((i + 1) * BLOCK_SIZE)]
            .try_into()
            .unwrap();
        let decrypted_block = aes::decrypt_block(block, key);
        output.extend(xor_blocks(&decrypted_block, prev_block));
        c = *block;
    }
    (output, c)
}

fn xor_blocks(a: &Block, b: &Block) -> Block {
    let mut output = [0u8; 16];
    zip(a, b).enumerate().for_each(|(i, (x, y))| {
        output[i] = x ^ y;
    });
    output
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let plaintext: &[u8] = &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let ciphertext: &[u8] = &[
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
            0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
            0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];
        let key: &[u8] = &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let iv: &Block = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let (encrypted, _new_iv) = encrypt(plaintext, key, iv);
        let (decrypted, _new_iv) = decrypt(ciphertext, key, iv);

        assert_eq!(ciphertext, encrypted);
        assert_eq!(plaintext, decrypted);
    }
}
