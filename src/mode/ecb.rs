use crate::{aes, Block, BLOCK_SIZE};

pub(crate) fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(
        0,
        plaintext.len() % BLOCK_SIZE,
        "Input length is not a multiply of block size."
    );

    let mut output = Vec::<u8>::with_capacity(plaintext.len());
    for i in 0..(plaintext.len() / BLOCK_SIZE) {
        let block: &Block = &plaintext[(i * BLOCK_SIZE)..((i + 1) * BLOCK_SIZE)]
            .try_into()
            .unwrap();
        let encrypted_block = aes::encrypt_block(block, key);
        output.extend(encrypted_block);
    }
    output
}

pub(crate) fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(
        0,
        ciphertext.len() % BLOCK_SIZE,
        "Input length is not a multiply of block size."
    );

    let mut output = Vec::<u8>::with_capacity(ciphertext.len());
    for i in 0..(ciphertext.len() / BLOCK_SIZE) {
        let block: &Block = &ciphertext[(i * BLOCK_SIZE)..((i + 1) * BLOCK_SIZE)]
            .try_into()
            .unwrap();
        let decrypted_block = aes::decrypt_block(block, key);
        output.extend(decrypted_block);
    }
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
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
            0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
            0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
        ];
        let key: &[u8] = &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];

        assert_eq!(ciphertext, encrypt(plaintext, key));
        assert_eq!(plaintext, decrypt(ciphertext, key));
    }
}
