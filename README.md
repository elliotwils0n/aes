# aes
Advanced Encryption Standard

<!-- badges template
[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![CI Status][actions-badge]][actions-url]
[![Dependencies Status][deps-badge]][deps-url]

[crates-badge]: https://img.shields.io/crates/v/0xdead.svg
[crates-url]: https://crates.io/crates/0xdead
[docs-badge]: https://docs.rs/0xdead/badge.svg
[docs-url]: https://docs.rs/0xdead
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE
[actions-badge]: https://github.com/elliotwils0n/0xdead/workflows/CI/badge.svg
[actions-url]: https://github.com/elliotwils0n/0xdead/actions?query=workflow%3ACI+branch%3Amaster
[deps-badge]: https://deps.rs/repo/github/elliotwils0n/0xdead/status.svg
[deps-url]: https://deps.rs/repo/github/elliotwils0n/0xdead
-->

[![MIT licensed][mit-badge]][mit-url]
[![CI Status][actions-badge]][actions-url]
[![Dependencies Status][deps-badge]][deps-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE
[actions-badge]: https://github.com/elliotwils0n/aes/workflows/CI/badge.svg
[actions-url]: https://github.com/elliotwils0n/aes/actions?query=workflow%3ACI+branch%3Amaster
[deps-badge]: https://deps.rs/repo/github/elliotwils0n/aes/status.svg
[deps-url]: https://deps.rs/repo/github/elliotwils0n/aes

## Disclaimer
> [!WARNING]
> Implementation of AES. It's done for my own research and should never be used outside of local playground.

## Usage
- Add Cargo.toml dependency
    ```toml
    [dependencies]
    aes = { git = "https://github.com/elliotwils0n/aes.git", branch = "master" }
    ```
- Example usage
    ```rust
    fn main() {
        // 0123456789abcdef
        let key = &[
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66,
        ];
        let plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Tincidunt tortor aliquam nulla facilisi cras. Dolor sit amet consectetur adipiscing elit. Aliquet porttitor lacus luctus accumsan tortor posuere ac ut. Quis imperdiet massa tincidunt nunc pulvinar sapien. Tortor at risus viverra adipiscing at in tellus integer. Vulputate mi sit amet mauris commodo quis imperdiet massa. Auctor augue mauris augue neque gravida in. Lobortis elementum nibh tellus molestie nunc non blandit massa enim. Arcu bibendum at varius vel pharetra vel. Magna fringilla urna porttitor rhoncus dolor. Eros in cursus turpis massa tincidunt dui. Aliquam purus sit amet luctus venenatis. Blah, blah, blah, blah, blah, blah! D:";
        let plaintext = plaintext.as_bytes();

        // ECB mode
        let ciphertext = aes::encrypt(plaintext, key, aes::Mode::Ecb);
        let plaintext_again = aes::decrypt(&ciphertext, key, aes::Mode::Ecb);
        assert_eq!(plaintext, plaintext_again);

        // CBC mode
        let iv = &[
            0x66, 0x65, 0x64, 63, 0x62, 0x61, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
            0x30,
        ];
        let ciphertext = aes::encrypt(plaintext, key, aes::Mode::Cbc(iv));
        let plaintext_again = aes::decrypt(&ciphertext, key, aes::Mode::Cbc(iv));
        assert_eq!(plaintext, plaintext_again);
    }
    ```
