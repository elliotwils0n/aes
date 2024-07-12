mod pkcs7;

#[derive(Debug, PartialEq)]
pub(crate) struct PaddingError(pub(crate) String);

pub(crate) trait Padder {
    fn pad(&self, input: &[u8]) -> Result<Vec<u8>, PaddingError>;
    fn unpad<'a>(&self, input: &'a [u8]) -> Result<&'a [u8], PaddingError>;
}

pub(crate) use pkcs7::PKCS7;
