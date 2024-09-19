use crate::{
    lookup::{RCON_LOOKUP, S_BOX},
    Block, Word, NB,
};

#[allow(clippy::identity_op, clippy::erasing_op)] // for readability
pub(crate) fn add_round_key(state: &mut Block, key_schedule: &[Word], nr: u8) {
    for c in 0..NB {
        state[0 * 4 + c] ^= key_schedule[nr as usize * NB + c][0];
        state[1 * 4 + c] ^= key_schedule[nr as usize * NB + c][1];
        state[2 * 4 + c] ^= key_schedule[nr as usize * NB + c][2];
        state[3 * 4 + c] ^= key_schedule[nr as usize * NB + c][3];
    }
}

// https://en.wikipedia.org/wiki/AES_key_schedule
pub(crate) fn key_expansion(key: &[u8], nr: usize) -> Vec<Word> {
    let nk = key.len() / 4;
    let mut w = Vec::<[u8; 4]>::with_capacity(NB * (nr + 1));
    let mut temp;

    for i in 0..nk {
        w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in nk..(NB * (nr + 1)) {
        temp = w[i - 1];
        if i % nk == 0 {
            temp = xor_words(&sub_word(&rot_word(&temp)), &rcon(i / nk));
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(&temp);
        }
        w.push(xor_words(&w[i - nk], &temp));
    }
    w
}

fn xor_words(a: &Word, b: &Word) -> Word {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

fn sub_word(word: &Word) -> Word {
    let mut sub = [0u8; 4];
    for i in 0..4 {
        let x = (word[i] & 0xF0) >> 4;
        let y = word[i] & 0x0F;
        sub[i] = S_BOX[x as usize * 16 + y as usize];
    }
    sub
}

fn rot_word(word: &[u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

fn rcon(i: usize) -> [u8; 4] {
    [RCON_LOOKUP[i - 1], 0, 0, 0]
}
