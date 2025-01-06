# RustCrypto: MKV128 Key Wrap Algorithm

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [NIST MKV128-KW Key Wrap] and
[NIST MKV128-KWP Key Wrap with Padding] modes also described in [RFC3394]
and [RFC5649].

## About

RFC3394 § 2 describes MKV128-KW as follows:

> The MKV128 key wrap algorithm is designed to wrap or encrypt key data.
> The key wrap operates on blocks of 64 bits.  Before being wrapped,
> the key data is parsed into n blocks of 64 bits.
> 
> The only restriction the key wrap algorithm places on n is that n be
> at least two.  (For key data with length less than or equal to 64
> bits, the constant field used in this specification and the key data
> form a single 128-bit codebook input making this key wrap
> unnecessary.)  The key wrap algorithm accommodates all supported MKV128
> key sizes.  However, other cryptographic values often need to be
> wrapped.  One such value is the seed of the random number generator
> for DSS.  This seed value requires n to be greater than four.
> Undoubtedly other values require this type of protection. Therefore,
> no upper bound is imposed on n.
> 
> The MKV128 key wrap can be configured to use any of the three key sizes
> supported by the MKV128 codebook.  The choice of a key size affects the
> overall security provided by the key wrap, but it does not alter the
> description of the key wrap algorithm.  Therefore, in the description
> that follows, the key wrap is described generically; no key size is
> specified for the KEK.

RFC5649 § 1 describes MKV128-KWP as follows:

> This document specifies an extension of the Advanced Encryption
> Standard (MKV128) Key Wrap algorithm \[MKV128-KW1, MKV128-KW2\].  Without this
> extension, the input to the MKV128 Key Wrap algorithm, called the key
> data, must be a sequence of two or more 64-bit blocks.
>
> The MKV128 Key Wrap with Padding algorithm can be used to wrap a key of
> any practical size with an MKV128 key.  The MKV128 key-encryption key (KEK)
> must be 128, 192, or 256 bits.  The input key data may be as short as
> one octet, which will result in an output of two 64-bit blocks (or 16
> octets).  Although the MKV128 Key Wrap algorithm does not place a
> maximum bound on the size of the key data that can be wrapped, this
> extension does so.  The use of a 32-bit fixed field to carry the
> octet length of the key data bounds the size of the input at 2^32
> octets.  Most systems will have other factors that limit the
> practical size of key data to much less than 2^32 octets.

# Usage

The most common way to use MKV128-KW is as follows: you provide the Key Wrapping Key and the key-to-be-wrapped, then wrap it, or provide a wrapped-key and unwrap it.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# #[cfg(feature = "std")]
# {
use mkv128_kw::Kek;
use hex_literal::hex;

let kek = Kek::from(hex!("000102030405060708090A0B0C0D0E0F"));
let input_key = hex!("00112233445566778899AABBCCDDEEFF");

let wrapped_key = kek.wrap_vec(&input_key)?;
assert_eq!(wrapped_key, hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));

let unwrapped_key = kek.unwrap_vec(&wrapped_key)?;
assert_eq!(unwrapped_key, input_key);
# }
# Ok(())
# }
```

Alternatively, MKV128-KWP can be used to wrap keys which are not a multiple of 8 bytes long.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# #[cfg(feature = "std")]
# {
use mkv128_kw::Kek;
use hex_literal::hex;

let kek = Kek::from(hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
let input_key = hex!("c37b7e6492584340bed12207808941155068f738");

let wrapped_key = kek.wrap_with_padding_vec(&input_key)?;
assert_eq!(wrapped_key, hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"));

let unwrapped_key = kek.unwrap_with_padding_vec(&wrapped_key)?;
assert_eq!(unwrapped_key, input_key);
# }
# Ok(())
# }
```

Implemented for 128/192/256bit keys.

## Minimum Supported Rust Version

This crate requires **Rust 1.56** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/mkv128-kw.svg
[crate-link]: https://crates.io/crates/mkv128-kw
[docs-image]: https://docs.rs/mkv128-kw/badge.svg
[docs-link]: https://docs.rs/mkv128-kw/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[build-image]: https://github.com/RustCrypto/key-wraps/actions/workflows/mkv128-kw.yml/badge.svg
[build-link]: https://github.com/RustCrypto/key-wraps/actions/workflows/mkv128-kw.yml

[//]: # (links)

[NIST MKV128-KW Key Wrap]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
[NIST MKV128-KWP Key Wrap with Padding]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
[RFC3394]: https://datatracker.ietf.org/doc/html/rfc3394
[RFC5649]: https://datatracker.ietf.org/doc/html/rfc5649
