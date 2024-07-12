mod aes;
mod dec;
mod enc;
mod key;
mod lookup;
mod mode;
mod padding;
mod state;

use padding::{Padder, PKCS7};

pub(crate) const NB: usize = 4;
pub(crate) const BLOCK_SIZE: usize = 16;

pub(crate) type State = [[u8; NB]; 4];
pub(crate) type Block = [u8; BLOCK_SIZE];
pub(crate) type Word = [u8; 4];

/// Different modes to use with aes block cipher encryption.
/// ECB dosen't need additional parameters but it is considered unsecured.
/// CBC requires initialization vector.
#[derive(Clone)]
pub enum Mode<'a> {
    Ecb,
    Cbc(&'a [u8; BLOCK_SIZE]),
}

/// Padding options to extend input to the block size.
#[derive(Clone)]
pub enum Padding {
    PKCS7,
}

#[allow(unused)]
#[derive(Debug)]
pub struct CipherError(String);

pub struct Cipher<'a> {
    encryptor: Encryptor<'a>,
    decryptor: Decryptor<'a>,
}

impl<'a> Cipher<'a> {
    pub fn init(key: &'a [u8], mode: Mode<'a>, padding: Padding) -> Result<Self, CipherError> {
        let encryptor = Encryptor::init(key, mode.clone(), padding.clone())?;
        let decryptor = Decryptor::init(key, mode, padding)?;
        Ok(Self {
            encryptor,
            decryptor,
        })
    }

    pub fn encryptor(&mut self) -> &mut Encryptor<'a> {
        &mut self.encryptor
    }

    pub fn decryptor(&mut self) -> &mut Decryptor<'a> {
        &mut self.decryptor
    }
}

pub trait Operations<'a> {
    fn init(key: &'a [u8], mode: Mode<'a>, padding: Padding) -> Result<Self, CipherError>
    where
        Self: Sized;
    fn update(&mut self, data: &[u8]) -> Vec<u8>;
    fn finalize(&mut self) -> Result<Vec<u8>, CipherError>;
}

pub struct Encryptor<'a> {
    key: &'a [u8],
    mode: Mode<'a>,
    padding: Padding,
    buffer: Vec<u8>,
}

impl<'a> Operations<'a> for Encryptor<'a> {
    fn init(key: &'a [u8], mode: Mode<'a>, padding: Padding) -> Result<Self, CipherError> {
        if ![16, 24, 32].contains(&key.len()) {
            return Err(CipherError(format!(
                "Ivalid key length for AES algorithm. Expected one of [128, 192, 256], got: {}",
                key.len() * 8
            )));
        };
        Ok(Self {
            key,
            mode,
            padding,
            buffer: Vec::with_capacity(BLOCK_SIZE),
        })
    }

    fn update(&mut self, data: &[u8]) -> Vec<u8> {
        let output_size = self.buffer.len() + (data.len() - (data.len() % BLOCK_SIZE));
        let mut output = Vec::with_capacity(output_size);

        // Extend buffer to match the block size.
        let buffer_ext_len = BLOCK_SIZE - self.buffer.len();
        let (buffer_ext, remaining) = data.split_at(buffer_ext_len);
        self.buffer.extend(buffer_ext);

        // Encrypt data from the buffer, append it to output and clear the buffer.
        let ciphertext = match self.mode {
            Mode::Ecb => mode::ecb::encrypt(&self.buffer, self.key),
            Mode::Cbc(iv) => mode::cbc::encrypt(&self.buffer, self.key, iv),
        };
        output.extend(ciphertext);
        self.buffer.clear();

        // Carry over leftovers for next update or finalize
        let (fixed_remaining, leftovers) =
            remaining.split_at(remaining.len() - (remaining.len() % BLOCK_SIZE));
        self.buffer.extend(leftovers);

        // Encrypt rest of the data and append to the output.
        let ciphertext = match self.mode {
            Mode::Ecb => mode::ecb::encrypt(fixed_remaining, self.key),
            Mode::Cbc(iv) => mode::cbc::encrypt(fixed_remaining, self.key, iv),
        };
        output.extend(ciphertext);

        output
    }

    fn finalize(&mut self) -> Result<Vec<u8>, CipherError> {
        let padder = match self.padding {
            Padding::PKCS7 => PKCS7::new(BLOCK_SIZE),
        };

        let plaintext = match padder.pad(&self.buffer) {
            Ok(pt) => pt,
            Err(err) => return Err(CipherError(err.0)),
        };

        let ciphertext = match self.mode {
            Mode::Ecb => mode::ecb::encrypt(&plaintext, self.key),
            Mode::Cbc(iv) => mode::cbc::encrypt(&plaintext, self.key, iv),
        };

        Ok(ciphertext)
    }
}

pub struct Decryptor<'a> {
    key: &'a [u8],
    mode: Mode<'a>,
    padding: Padding,
    buffer: Vec<u8>,
}

impl<'a> Operations<'a> for Decryptor<'a> {
    fn init(key: &'a [u8], mode: Mode<'a>, padding: Padding) -> Result<Self, CipherError> {
        if ![16, 24, 32].contains(&key.len()) {
            return Err(CipherError(format!(
                "Ivalid key length for AES algorithm. Expected one of [128, 192, 256], got: {}",
                key.len() * 8
            )));
        };
        Ok(Self {
            key,
            mode,
            padding,
            buffer: Vec::with_capacity(BLOCK_SIZE),
        })
    }

    fn update(&mut self, data: &[u8]) -> Vec<u8> {
        // todo: refactor
        let mut buf = Vec::<u8>::with_capacity(self.buffer.len() + data.len());
        buf.extend(&self.buffer);
        buf.extend(data);
        self.buffer.clear();

        if buf.len() <= BLOCK_SIZE {
            self.buffer.extend(&buf);
            return vec![];
        }

        let (prior, last_block) = buf.split_at(buf.len() - BLOCK_SIZE);
        let mut output = Vec::with_capacity(prior.len());

        let ciphertext = match self.mode {
            Mode::Ecb => mode::ecb::decrypt(prior, self.key),
            Mode::Cbc(iv) => mode::cbc::decrypt(prior, self.key, iv),
        };
        self.buffer.extend(last_block);
        output.extend(ciphertext);

        output
    }

    fn finalize(&mut self) -> Result<Vec<u8>, CipherError> {
        let padder = match self.padding {
            Padding::PKCS7 => PKCS7::new(BLOCK_SIZE),
        };

        let plaintext = match self.mode {
            Mode::Ecb => mode::ecb::decrypt(&self.buffer, self.key),
            Mode::Cbc(iv) => mode::cbc::decrypt(&self.buffer, self.key, iv),
        };

        let unpadded_plaintext = match padder.unpad(&plaintext) {
            Ok(pt) => pt,
            Err(err) => return Err(CipherError(err.0)),
        };

        Ok(unpadded_plaintext.to_vec())
    }
}
