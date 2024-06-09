use crate::{
    lookup::{INV_S_BOX, MULT_11_LOOKUP, MULT_13_LOOKUP, MULT_14_LOOKUP, MULT_9_LOOKUP},
    State,
};

pub(crate) fn sub_bytes(state: &mut State) {
    for r in 0..state.len() {
        for c in 0..state[0].len() {
            let x = (state[r][c] & 0xF0) >> 4;
            let y = state[r][c] & 0x0F;
            state[r][c] = INV_S_BOX[x as usize * 16 + y as usize];
        }
    }
}

pub(crate) fn shift_rows(state: &mut State) {
    let state_clone = state.clone();
    state[1][0] = state_clone[1][3];
    state[1][1] = state_clone[1][0];
    state[1][2] = state_clone[1][1];
    state[1][3] = state_clone[1][2];

    state[2][0] = state_clone[2][2];
    state[2][1] = state_clone[2][3];
    state[2][2] = state_clone[2][0];
    state[2][3] = state_clone[2][1];

    state[3][0] = state_clone[3][1];
    state[3][1] = state_clone[3][2];
    state[3][2] = state_clone[3][3];
    state[3][3] = state_clone[3][0];
}

pub(crate) fn mix_columns(state: &mut State) {
    for c in 0..state[0].len() {
        mix_column(state, c);
    }
}

// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Matrix_representation
fn mix_column(state: &mut State, col: usize) {
    let (b0, b1, b2, b3) = (
        state[0][col] as usize,
        state[1][col] as usize,
        state[2][col] as usize,
        state[3][col] as usize,
    );
    state[0][col] =
        MULT_14_LOOKUP[b0] ^ MULT_11_LOOKUP[b1] ^ MULT_13_LOOKUP[b2] ^ MULT_9_LOOKUP[b3];
    state[1][col] =
        MULT_9_LOOKUP[b0] ^ MULT_14_LOOKUP[b1] ^ MULT_11_LOOKUP[b2] ^ MULT_13_LOOKUP[b3];
    state[2][col] =
        MULT_13_LOOKUP[b0] ^ MULT_9_LOOKUP[b1] ^ MULT_14_LOOKUP[b2] ^ MULT_11_LOOKUP[b3];
    state[3][col] =
        MULT_11_LOOKUP[b0] ^ MULT_13_LOOKUP[b1] ^ MULT_9_LOOKUP[b2] ^ MULT_14_LOOKUP[b3];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_columns_test() {
        // https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mut state = [
            [0x8e, 0x9f, 0xd5, 0x4d],
            [0x4d, 0xdc, 0xd5, 0x7e],
            [0xa1, 0x58, 0xd7, 0xbd],
            [0xbc, 0x9d, 0xd6, 0xf8],
        ];
        let expected_state = [
            [0xdb, 0xf2, 0xd4, 0x2d],
            [0x13, 0x0a, 0xd4, 0x26],
            [0x53, 0x22, 0xd4, 0x31],
            [0x45, 0x5c, 0xd5, 0x4c],
        ];
        mix_columns(&mut state);
        assert_eq!(expected_state, state);
    }

    #[test]
    fn mix_columns_test2() {
        // https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mut state = [
            [0x01, 0xc6, 0x01, 0xc6],
            [0x01, 0xc6, 0x01, 0xc6],
            [0x01, 0xc6, 0x01, 0xc6],
            [0x01, 0xc6, 0x01, 0xc6],
        ];
        let expected_state = state.clone();
        mix_columns(&mut state);
        assert_eq!(expected_state, state);
    }
}
