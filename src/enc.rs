use crate::{
    lookup::{MULT_2_LOOKUP, MULT_3_LOOKUP, S_BOX},
    Block, NB,
};

pub(crate) fn sub_bytes(state: &mut Block) {
    for r in 0..4 {
        for c in 0..NB {
            let x = (state[r * 4 + c] & 0xF0) >> 4;
            let y = state[r * 4 + c] & 0x0F;
            state[r * 4 + c] = S_BOX[x as usize * 16 + y as usize];
        }
    }
}

#[allow(clippy::identity_op)] // for readability
pub(crate) fn shift_rows(state: &mut Block) {
    // todo: mem swap
    let state_clone = state.to_vec();
    state[1 * 4 + 0] = state_clone[1 * 4 + 1];
    state[1 * 4 + 1] = state_clone[1 * 4 + 2];
    state[1 * 4 + 2] = state_clone[1 * 4 + 3];
    state[1 * 4 + 3] = state_clone[1 * 4 + 0];

    state[2 * 4 + 0] = state_clone[2 * 4 + 2];
    state[2 * 4 + 1] = state_clone[2 * 4 + 3];
    state[2 * 4 + 2] = state_clone[2 * 4 + 0];
    state[2 * 4 + 3] = state_clone[2 * 4 + 1];

    state[3 * 4 + 0] = state_clone[3 * 4 + 3];
    state[3 * 4 + 1] = state_clone[3 * 4 + 0];
    state[3 * 4 + 2] = state_clone[3 * 4 + 1];
    state[3 * 4 + 3] = state_clone[3 * 4 + 2];
}

pub(crate) fn mix_columns(state: &mut Block) {
    for c in 0..NB {
        mix_column(state, c);
    }
}

// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Matrix_representation
#[allow(clippy::identity_op, clippy::erasing_op)] // for readability
fn mix_column(state: &mut Block, col: usize) {
    let (b0, b1, b2, b3) = (
        state[0 * 4 + col],
        state[1 * 4 + col],
        state[2 * 4 + col],
        state[3 * 4 + col],
    );
    state[0 * 4 + col] = MULT_2_LOOKUP[b0 as usize] ^ MULT_3_LOOKUP[b1 as usize] ^ b2 ^ b3;
    state[1 * 4 + col] = b0 ^ MULT_2_LOOKUP[b1 as usize] ^ MULT_3_LOOKUP[b2 as usize] ^ b3;
    state[2 * 4 + col] = b0 ^ b1 ^ MULT_2_LOOKUP[b2 as usize] ^ MULT_3_LOOKUP[b3 as usize];
    state[3 * 4 + col] = MULT_3_LOOKUP[b0 as usize] ^ b1 ^ b2 ^ MULT_2_LOOKUP[b3 as usize];
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    #[test]
    fn mix_columns_test() {
        // https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mut state = [
            0xdb, 0xf2, 0xd4, 0x2d,
            0x13, 0x0a, 0xd4, 0x26,
            0x53, 0x22, 0xd4, 0x31,
            0x45, 0x5c, 0xd5, 0x4c,
        ];
        let expected_state = [
            0x8e, 0x9f, 0xd5, 0x4d,
            0x4d, 0xdc, 0xd5, 0x7e,
            0xa1, 0x58, 0xd7, 0xbd,
            0xbc, 0x9d, 0xd6, 0xf8,
        ];
        mix_columns(&mut state);
        assert_eq!(expected_state, state);
    }

    #[test]
    fn mix_columns_test2() {
        // https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mut state = [
            0x01, 0xc6, 0x01, 0xc6,
            0x01, 0xc6, 0x01, 0xc6,
            0x01, 0xc6, 0x01, 0xc6,
            0x01, 0xc6, 0x01, 0xc6,
        ];
        mix_columns(&mut state);
        assert_eq!(state, state);
    }
}
