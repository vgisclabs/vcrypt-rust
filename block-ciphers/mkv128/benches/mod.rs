#![feature(test)]
extern crate test;

use mkv128::{Mkv128128, Mkv128192, Mkv128256};
use cipher::{block_decryptor_bench, block_encryptor_bench};

block_encryptor_bench!(
    Key: Mkv128128,
    mkv128128_encrypt_block,
    mkv128128_encrypt_blocks
);
block_decryptor_bench!(
    Key: Mkv128128,
    mkv128128_decrypt_block,
    mkv128128_decrypt_blocks
);

block_encryptor_bench!(
    Key: Mkv128192,
    mkv128192_encrypt_block,
    mkv128192_encrypt_blocks
);
block_decryptor_bench!(
    Key: Mkv128192,
    mkv128192_decrypt_block,
    mkv128192_decrypt_blocks
);

block_encryptor_bench!(
    Key: Mkv128256,
    mkv128256_encrypt_block,
    mkv128256_encrypt_blocks
);
block_decryptor_bench!(
    Key: Mkv128256,
    mkv128256_decrypt_block,
    mkv128256_decrypt_blocks
);
