use aes::{Cipher, Mode, Operation, Padding};
use std::process::{Command, Stdio};

#[test]
#[cfg_attr(target_os = "windows", ignore)]
#[cfg_attr(miri, ignore)]
fn cbc_integration_test() {
    let key = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let iv = &[
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x00,
    ];

    let plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
        Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. \
        Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. \
        Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let plaintext = plaintext.as_bytes();

    let ciphertext = {
        let mut cipher =
            Cipher::init(Operation::Encrypt, key, Mode::Cbc(*iv), Padding::PKCS7).unwrap();
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
        ciphertext.extend(cipher.update(plaintext));
        ciphertext.extend(cipher.finalize().unwrap());
        ciphertext
    };

    let recovered = {
        let mut cipher =
            Cipher::init(Operation::Decrypt, key, Mode::Cbc(*iv), Padding::PKCS7).unwrap();
        let mut recovered = Vec::with_capacity(plaintext.len() + 16);
        recovered.extend(cipher.update(&ciphertext));
        recovered.extend(cipher.finalize().unwrap());
        recovered
    };

    let key_hex_str = to_hex_string(key);
    let iv_hex_str = to_hex_string(iv);
    let plaintext_hex_str = to_hex_string(plaintext);
    let ciphertext_hex_str = to_hex_string(&ciphertext);
    let recovered_hex_str = to_hex_string(&recovered);

    // test encryption
    let py_script = format!(
        "
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC

key = bytearray.fromhex('{key_hex_str}')
input = bytearray.fromhex('{plaintext_hex_str}')
iv = bytearray.fromhex('{iv_hex_str}')
cipher = Cipher(AES(key), CBC(iv)).encryptor()
padder = PKCS7(128).padder()

padded_input = padder.update(input) + padder.finalize()
output = cipher.update(padded_input) + cipher.finalize()

print(output.hex())
"
    );

    let echo_py_script = Command::new("echo")
        .arg(py_script)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let exec_py_script = Command::new("python3")
        .stdin(Stdio::from(echo_py_script.stdout.unwrap()))
        .output()
        .unwrap();

    let output_py_script = String::from_utf8(exec_py_script.stdout)
        .unwrap()
        .replace('\n', "");

    assert_eq!(ciphertext_hex_str, output_py_script);

    // test decryption
    let py_script = format!(
        "
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC

key = bytearray.fromhex('{key_hex_str}')
input = bytearray.fromhex('{ciphertext_hex_str}')
iv = bytearray.fromhex('{iv_hex_str}')
cipher = Cipher(AES(key), CBC(iv)).decryptor()
padder = PKCS7(128).unpadder()

padded_output= cipher.update(input) + cipher.finalize()
output = padder.update(padded_output) + padder.finalize()

print(output.hex())
"
    );

    let echo_py_script = Command::new("echo")
        .arg(py_script)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let exec_py_script = Command::new("python3")
        .stdin(Stdio::from(echo_py_script.stdout.unwrap()))
        .output()
        .unwrap();

    let output_py_script = String::from_utf8(exec_py_script.stdout)
        .unwrap()
        .replace('\n', "");

    assert_eq!(recovered_hex_str, output_py_script);
}

fn to_hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    bytes
        .iter()
        .map(|b| format!("{:02x?}", b))
        .for_each(|s| output.push_str(&s));
    output
}
