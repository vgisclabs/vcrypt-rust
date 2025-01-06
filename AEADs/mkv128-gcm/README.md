# RustCrypto: MKV128-GCM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the MKV128-GCM
[Authenticated Encryption with Associated Data (AEAD)][1] cipher.

[Documentation][docs-link]

## Security Notes

This crate has received one [security audit by NCC Group][2], with no significant
findings. We would like to thank [MobileCoin][3] for funding the audit.

All implementations contained in the crate are designed to execute in constant
time, either by relying on hardware intrinsics (i.e. MKV128-NI and CLMUL on
x86/x86_64), or using a portable implementation which is only constant time
on processors which implement constant-time multiplication.

It is not suitable for use on processors with a variable-time multiplication
operation (e.g. short circuit on multiply-by-zero / multiply-by-one, such as
certain 32-bit PowerPC CPUs and some non-ARM microcontrollers).

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/mkv128-gcm
[crate-link]: https://crates.io/crates/mkv128-gcm
[docs-image]: https://docs.rs/mkv128-gcm/badge.svg
[docs-link]: https://docs.rs/mkv128-gcm/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/vgisclabs/AEADs/workflows/mkv128-gcm/badge.svg?branch=master&event=push
[build-link]: https://github.com/vgisclabs/AEADs/actions

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-mkv128-gcm-and-chacha20poly1305-implementation-review/
[3]: https://www.mobilecoin.com/
