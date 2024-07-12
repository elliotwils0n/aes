use aes::Operations;

fn main() {
    let key = &[
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66,
    ];
    let iv = [
        0x66, 0x65, 0x64, 63, 0x62, 0x61, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
        0x30,
    ];
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
    let mut cipher = match aes::Cipher::init(key, aes::Mode::Cbc(iv), aes::Padding::PKCS7) {
        Ok(c) => c,
        Err(err) => panic!("{:?}", err),
    };
    let mut ciphertext = Vec::<u8>::new();
    for p in plaintext {
        let c = cipher.encryptor().update(p.as_bytes());
        ciphertext.extend(c);
    }
    let c = match cipher.encryptor().finalize() {
        Ok(f) => f,
        Err(err) => panic!("{:?}", err),
    };
    ciphertext.extend(c);

    // Decrypt data
    let mut cipher = match aes::Cipher::init(key, aes::Mode::Cbc(iv), aes::Padding::PKCS7) {
        Ok(c) => c,
        Err(err) => panic!("{:?}", err),
    };
    let mut recovered = Vec::<u8>::with_capacity(ciphertext.len());
    let c = cipher.decryptor().update(&ciphertext);
    recovered.extend(c);
    let c = match cipher.decryptor().finalize() {
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

    println!("CBC mode works fine!");
}
