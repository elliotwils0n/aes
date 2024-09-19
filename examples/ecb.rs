use aes::{Cipher, Mode, Operation, Padding};

fn main() {
    let key = "0123456789abcdef".as_bytes();
    let plaintext = [
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
        "Tincidunt tortor aliquam nulla facilisi cras.",
        "Dolor sit amet consectetur adipiscing elit.",
        "Aliquet porttitor lacus luctus accumsan tortor posuere ac ut.",
        "Quis imperdiet massa tincidunt nunc pulvinar sapien.",
        "Tortor at risus viverra adipiscing at in tellus integer.",
        "Vulputate mi sit amet mauris commodo quis imperdiet massa.",
        "Auctor augue mauris augue neque gravida in.",
        "Lobortis elementum nibh tellus molestie nunc non blandit massa enim.",
        "Arcu bibendum at varius vel pharetra vel.",
        "Magna fringilla urna porttitor rhoncus dolor.",
        "Eros in cursus turpis massa tincidunt dui.",
        "Aliquam purus sit amet luctus venenatis."];

    // Encrypt data
    let mut cipher = match Cipher::init(Operation::Encrypt, key, Mode::Ecb, Padding::PKCS7) {
        Ok(c) => c,
        Err(err) => panic!("{:?}", err),
    };

    let mut ciphertext = Vec::<u8>::new();
    for p in plaintext {
        let c = cipher.update(p.as_bytes());
        ciphertext.extend(c);
    }
    let c = match cipher.finalize() {
        Ok(f) => f,
        Err(err) => panic!("{:?}", err),
    };
    ciphertext.extend(c);

    // Decrypt data
    let mut cipher = match Cipher::init(Operation::Decrypt, key, Mode::Ecb, Padding::PKCS7) {
        Ok(c) => c,
        Err(err) => panic!("{:?}", err),
    };
    let mut recovered = Vec::<u8>::with_capacity(ciphertext.len());
    let c = cipher.update(&ciphertext);
    recovered.extend(c);
    let c = match cipher.finalize() {
        Ok(f) => f,
        Err(err) => panic!("{:?}", err),
    };
    recovered.extend(c);

    // Check recovered plaintext
    let plaintext = plaintext
        .iter()
        .flat_map(|s| s.as_bytes())
        .copied()
        .collect::<Vec<u8>>();

    // lengths are different because of padding
    assert_ne!(plaintext.len(), ciphertext.len());
    // lengths are the same after decryption because of unpadding
    assert_eq!(recovered.len(), plaintext.len());
    // recovered plaintext is the same as one before encryption
    assert_eq!(recovered, plaintext);

    println!("ECB mode works fine!");
}
