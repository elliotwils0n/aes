mod pkcs7;

#[derive(Debug, PartialEq)]
pub struct PaddingError(String);

pub trait Padder {
    fn pad(input: &[u8], size: usize) -> Result<Vec<u8>, PaddingError>;
    fn unpad(input: &[u8], size: usize) -> Result<&[u8], PaddingError>;
}
