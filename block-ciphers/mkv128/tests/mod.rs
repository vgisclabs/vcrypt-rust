//! Test vectors are from NESSIE:
//! <https://www.cosic.esat.kuleuven.be/nessie/testvectors/>

cipher::block_cipher_test!(mkv128128_test, "mkv128128", mkv128::Mkv128128);
cipher::block_cipher_test!(mkv128192_test, "mkv128192", mkv128::Mkv128192);
cipher::block_cipher_test!(mkv128256_test, "mkv128256", mkv128::Mkv128256);
