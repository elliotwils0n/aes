use super::{Padder, PaddingError};

pub struct PKCS7;

impl Padder for PKCS7 {
    fn pad(input: &[u8], size: usize) -> Result<Vec<u8>, PaddingError> {
        if input.len() > size {
            return Err(PaddingError(format!(
                "Input size ({}) exceeds expected block size ({size}).",
                input.len()
            )));
        }
        let pad_len = size - input.len();
        let mut output = Vec::<u8>::with_capacity(size);
        output.extend(input);
        (0..(pad_len)).for_each(|_| output.push(pad_len as u8));
        Ok(output)
    }

    fn unpad(input: &[u8], size: usize) -> Result<&[u8], PaddingError> {
        if input.len() != size {
            return Err(PaddingError(format!(
                "Input size ({}) is not equal to block size ({size}).",
                input.len()
            )));
        }
        let pad_len = input[input.len() - 1];
        let pad_start = input.len() - pad_len as usize;
        if input[pad_start..].iter().all(|x| *x == pad_len) {
            Ok(&input[..pad_start])
        } else {
            Ok(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_err_pad_when_input_bigger_than_block_size() {
        let input = [0u8; 17];
        let expected_result = Err(PaddingError(String::from(
            "Input size (17) exceeds expected block size (16).",
        )));
        let result = PKCS7::pad(&input, 16);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn should_pad_0() {
        let input = [0u8; 16];
        let expected_output = vec![0u8; 16];
        let padded_input = PKCS7::pad(&input, 16);
        assert_eq!(Ok(expected_output), padded_input);
    }

    #[test]
    fn should_pad_4() {
        let input = [0u8; 12];
        let expected_output: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4];
        let padded_input = PKCS7::pad(&input, 16);
        assert_eq!(Ok(expected_output), padded_input);
    }

    #[test]
    fn should_pad_16() {
        let input = [16u8; 16];
        let expected_output = vec![16u8; 16];
        let unpadded_input = PKCS7::pad(&input, 16);
        assert_eq!(Ok(expected_output), unpadded_input);
    }

    #[test]
    fn should_err_unpad_when_input_not_equal_to_block_size() {
        let input = [0u8; 17];
        let expected_result = Err(PaddingError(String::from(
            "Input size (17) is not equal to block size (16).",
        )));
        let result = PKCS7::unpad(&input, 16);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn should_unpad_0() {
        let input = [0u8; 16];
        let expected_output: &[u8] = &[0u8; 16];
        let unpadded_input = PKCS7::unpad(&input, 16);
        assert_eq!(Ok(expected_output), unpadded_input);
    }

    #[test]
    fn should_unpad_4() {
        let input = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4];
        let expected_output = &input[0..12];
        let unpadded_input = PKCS7::unpad(&input, 16);
        assert_eq!(Ok(expected_output), unpadded_input);
    }

    #[test]
    fn should_unpad_16() {
        let input = [16u8; 16];
        let expected_output: &[u8] = &[];
        let unpadded_input = PKCS7::unpad(&input, 16);
        assert_eq!(Ok(expected_output), unpadded_input);
    }
}
