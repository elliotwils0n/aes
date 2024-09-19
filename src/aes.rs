use crate::{dec, enc, key, state, Block};

pub(crate) fn encrypt_block(plaintext: &Block, key: &[u8]) -> Block {
    let nr = get_nr(key.len() * 8);
    let mut state = state::state_from_bytes(plaintext);
    let key_schedule = key::key_expansion(key, nr as usize);

    key::add_round_key(&mut state, &key_schedule, 0);

    for round in 1..nr {
        enc::sub_bytes(&mut state);
        enc::shift_rows(&mut state);
        enc::mix_columns(&mut state);
        key::add_round_key(&mut state, &key_schedule, round);
    }

    enc::sub_bytes(&mut state);
    enc::shift_rows(&mut state);
    key::add_round_key(&mut state, &key_schedule, nr);

    state::state_to_bytes(state)
}

pub(crate) fn decrypt_block(ciphertext: &Block, key: &[u8]) -> Block {
    let nr = get_nr(key.len() * 8);
    let mut state = state::state_from_bytes(ciphertext);
    let key_schedule = key::key_expansion(key, nr as usize);

    key::add_round_key(&mut state, &key_schedule, nr);

    for round in (1..nr).rev() {
        dec::shift_rows(&mut state);
        dec::sub_bytes(&mut state);
        key::add_round_key(&mut state, &key_schedule, round);
        dec::mix_columns(&mut state);
    }

    dec::shift_rows(&mut state);
    dec::sub_bytes(&mut state);
    key::add_round_key(&mut state, &key_schedule, 0);

    state::state_to_bytes(state)
}

fn get_nr(key_bits_len: usize) -> u8 {
    match key_bits_len {
        128 => 10,
        192 => 12,
        256 => 14,
        _ => panic!("Invalid key length. Expected one of 128, 192, 256, got {key_bits_len}."),
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn working_128() {
        let plaintext = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let key = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let expected_ciphertext = &[
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let ciphertext = encrypt_block(plaintext, key);
        let recovered_plaintext = decrypt_block(&ciphertext, key);

        assert_eq!(&ciphertext, expected_ciphertext);
        assert_eq!(&recovered_plaintext, plaintext);
    }

    #[test]
    fn working_192() {
        let plaintext = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let key = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let expected_ciphertext = &[
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
        ];

        let ciphertext = encrypt_block(plaintext, key);
        let recovered_plaintext = decrypt_block(&ciphertext, key);

        assert_eq!(&ciphertext, expected_ciphertext);
        assert_eq!(&recovered_plaintext, plaintext);
    }

    #[test]
    fn working_256() {
        let plaintext = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let key = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected_ciphertext = &[
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        let ciphertext = encrypt_block(plaintext, key);
        let recovered_plaintext = decrypt_block(&ciphertext, key);

        assert_eq!(&ciphertext, expected_ciphertext);
        assert_eq!(&recovered_plaintext, plaintext);
    }
}
