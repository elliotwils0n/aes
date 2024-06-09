use crate::{Block, State, NB};

pub(crate) fn state_from_bytes(input: &Block) -> State {
    let mut state = [[0u8; NB]; 4];
    for r in 0..(state.len()) {
        for c in 0..NB {
            state[r][c] = input[r + 4 * c];
        }
    }
    state
}

pub(crate) fn state_to_bytes(state: State) -> Block {
    let mut output = [0; 4 * NB];
    for r in 0..state.len() {
        for c in 0..NB {
            output[r + 4 * c] = state[r][c];
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_translation() {
        let before = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let after = state_to_bytes(state_from_bytes(&before));
        assert_eq!(before, after);
    }
}
