mod pkcs7;

#[derive(Debug, PartialEq)]
pub struct PaddingError(String);

pub trait Padder {
    fn pad(&self, input: &[u8]) -> Result<Vec<u8>, PaddingError>;
    fn unpad<'a>(&self, input: &'a [u8]) -> Result<&'a [u8], PaddingError>;
}
