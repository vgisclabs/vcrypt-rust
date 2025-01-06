//!
//! Mkv128
//! (C) 2014,2024 Ho Sy Tan <hstan@vgisc.com>
//!

use core::fmt;

use cipher::{
    consts::{U16, U24, U32},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consts::{
    MKV128_IL0, MKV128_IL1, MKV128_IL2, MKV128_IL3, MKV128_IL4, MKV128_L0, MKV128_L1, MKV128_L2,
    MKV128_L3, MKV128_L4, MKV128_ROUNDS_128, MKV128_ROUNDS_192, MKV128_ROUNDS_256,
};

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::iter;
use std::path::{Path, PathBuf};

fn set_initial_key(rounds: usize, key: &[u8], block1: &mut [u32], block2: &mut [u32]) {
    block1[0] = u32::from_be_bytes(key[0..4].try_into().unwrap());
    block1[1] = u32::from_be_bytes(key[4..8].try_into().unwrap());
    block1[2] = u32::from_be_bytes(key[8..12].try_into().unwrap());
    block1[3] = u32::from_be_bytes(key[12..16].try_into().unwrap());

    println!("-- set_initial_key - rounds = {}", rounds);
    println!("-- set_initial_key - key = {:02X?}", key);

    if rounds == MKV128_ROUNDS_128 {
        block2[0] = block1[0] ^ 0xFFFFFFFF;
        block2[1] = block1[1] ^ 0xFFFFFFFF;
        block2[2] = block1[2] ^ 0xFFFFFFFF;
        block2[3] = block1[3] ^ 0xFFFFFFFF;
    }

    if rounds == MKV128_ROUNDS_192 {
        block2[0] = u32::from_be_bytes(key[16..20].try_into().unwrap());
        block2[1] = u32::from_be_bytes(key[20..24].try_into().unwrap());
        block2[2] = block1[2] ^ 0xFFFFFFFF;
        block2[3] = block1[3] ^ 0xFFFFFFFF;
    }

    if rounds == MKV128_ROUNDS_256 {
        block2[0] = u32::from_be_bytes(key[16..20].try_into().unwrap());
        block2[1] = u32::from_be_bytes(key[20..24].try_into().unwrap());
        block2[2] = u32::from_be_bytes(key[24..28].try_into().unwrap());
        block2[3] = u32::from_be_bytes(key[28..32].try_into().unwrap());
    }
}

fn set_encrypt_key(rounds: usize, key: &[u8], rk: &mut [u32]) {
    let block1: &mut [u32] = &mut [0u32; 4];
    let block2: &mut [u32] = &mut [0u32; 4];
    let tmp: &mut [u32] = &mut [0u32; 4];

    println!("-- set_encrypt_key - rounds = {}", rounds);
    println!("-- set_encrypt_key - key = {:02X?}", key);
    println!("-- set_encrypt_key - rk = {:02X?}", rk);

    rk[0] = u32::from_be_bytes(key[0..4].try_into().unwrap());
    rk[1] = u32::from_be_bytes(key[4..8].try_into().unwrap());
    rk[2] = u32::from_be_bytes(key[8..12].try_into().unwrap());
    rk[3] = u32::from_be_bytes(key[12..16].try_into().unwrap());

    println!("-- set_encrypt_key - rk = {:02X?}", rk);

    set_initial_key(rounds, key, block1, block2);

    println!("-- set_encrypt_key - rk = {:02X?}", rk);

    for i in 0..rounds {
        println!("-- i = {}", i);
        block1[3] = block1[3] ^ ((2 * i + 1) as u32);

        tmp[0] = MKV128_L0[((block1[0] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block1[0] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block1[0] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block1[0] & 0xFF) as usize];
        tmp[1] = MKV128_L0[((block1[1] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block1[1] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block1[1] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block1[1] & 0xFF) as usize];
        tmp[2] = MKV128_L0[((block1[2] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block1[2] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block1[2] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block1[2] & 0xFF) as usize];
        tmp[3] = MKV128_L0[((block1[3] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block1[3] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block1[3] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block1[3] & 0xFF) as usize];

        block1[0] = MKV128_L4[((tmp[0] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[0] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[0] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[0] & 0xFF) as usize] >> 24);
        block1[1] = MKV128_L4[((tmp[1] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[1] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[1] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[1] & 0xFF) as usize] >> 24);
        block1[2] = MKV128_L4[((tmp[2] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[2] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[2] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[2] & 0xFF) as usize] >> 24);
        block1[3] = MKV128_L4[((tmp[3] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[3] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[3] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[3] & 0xFF) as usize] >> 24);

        tmp[0] = block1[1] ^ block1[2] ^ block1[3];
        tmp[1] = block1[0] ^ block1[2] ^ block1[3];
        tmp[2] = block1[0] ^ block1[1] ^ block1[3];
        tmp[3] = block1[0] ^ block1[1] ^ block1[2];

        block1[0] = MKV128_L0[((tmp[0] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[0] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[0] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[0] & 0xFF) as usize];
        block1[1] = MKV128_L0[((tmp[1] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[1] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[1] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[1] & 0xFF) as usize];
        block1[2] = MKV128_L0[((tmp[2] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[2] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[2] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[2] & 0xFF) as usize];
        block1[3] = MKV128_L0[((tmp[3] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[3] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[3] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[3] & 0xFF) as usize];

        tmp[0] = MKV128_L4[((block1[0] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block1[0] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block1[0] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block1[0] & 0xFF) as usize] >> 24);
        tmp[1] = MKV128_L4[((block1[1] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block1[1] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block1[1] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block1[1] & 0xFF) as usize] >> 24);
        tmp[2] = MKV128_L4[((block1[2] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block1[2] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block1[2] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block1[2] & 0xFF) as usize] >> 24);
        tmp[3] = MKV128_L4[((block1[3] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block1[3] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block1[3] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block1[3] & 0xFF) as usize] >> 24);

        block1[0] = tmp[1] ^ tmp[2] ^ tmp[3];
        block1[1] = tmp[0] ^ tmp[2] ^ tmp[3];
        block1[2] = tmp[0] ^ tmp[1] ^ tmp[3];
        block1[3] = tmp[0] ^ tmp[1] ^ tmp[2];

        block2[3] = block2[3] ^ ((2 * i + 2) as u32);

        tmp[0] = MKV128_L0[((block2[0] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block2[0] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block2[0] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block2[0] & 0xFF) as usize];
        tmp[1] = MKV128_L0[((block2[1] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block2[1] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block2[1] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block2[1] & 0xFF) as usize];
        tmp[2] = MKV128_L0[((block2[2] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block2[2] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block2[2] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block2[2] & 0xFF) as usize];
        tmp[3] = MKV128_L0[((block2[3] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((block2[3] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((block2[3] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(block2[3] & 0xFF) as usize];

        block2[0] = MKV128_L4[((tmp[0] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[0] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[0] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[0] & 0xFF) as usize] >> 24);
        block2[1] = MKV128_L4[((tmp[1] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[1] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[1] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[1] & 0xFF) as usize] >> 24);
        block2[2] = MKV128_L4[((tmp[2] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[2] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[2] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[2] & 0xFF) as usize] >> 24);
        block2[3] = MKV128_L4[((tmp[3] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((tmp[3] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((tmp[3] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(tmp[3] & 0xFF) as usize] >> 24);

        tmp[0] = block2[1] ^ block2[2] ^ block2[3];
        tmp[1] = block2[0] ^ block2[2] ^ block2[3];
        tmp[2] = block2[0] ^ block2[1] ^ block2[3];
        tmp[3] = block2[0] ^ block2[1] ^ block2[2];

        block2[0] = MKV128_L0[((tmp[0] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[0] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[0] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[0] & 0xFF) as usize];
        block2[1] = MKV128_L0[((tmp[1] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[1] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[1] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[1] & 0xFF) as usize];
        block2[2] = MKV128_L0[((tmp[2] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[2] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[2] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[2] & 0xFF) as usize];
        block2[3] = MKV128_L0[((tmp[3] >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((tmp[3] >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((tmp[3] >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(tmp[3] & 0xFF) as usize];

        tmp[0] = MKV128_L4[((block2[0] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block2[0] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block2[0] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block2[0] & 0xFF) as usize] >> 24);
        tmp[1] = MKV128_L4[((block2[1] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block2[1] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block2[1] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block2[1] & 0xFF) as usize] >> 24);
        tmp[2] = MKV128_L4[((block2[2] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block2[2] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block2[2] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block2[2] & 0xFF) as usize] >> 24);
        tmp[3] = MKV128_L4[((block2[3] >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((block2[3] >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((block2[3] >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(block2[3] & 0xFF) as usize] >> 24);

        block2[0] = tmp[1] ^ tmp[2] ^ tmp[3];
        block2[1] = tmp[0] ^ tmp[2] ^ tmp[3];
        block2[2] = tmp[0] ^ tmp[1] ^ tmp[3];
        block2[3] = tmp[0] ^ tmp[1] ^ tmp[2];

        tmp[0] = block2[0];
        tmp[1] = block2[1];
        tmp[2] = block2[2];
        tmp[3] = block2[3];

        rk[4 * (2 * i + 1) + 4] = block2[0];
        block2[0] = tmp[0] ^ block1[0];
        rk[4 * (2 * i + 1) + 5] = block2[1];
        block2[1] = tmp[1] ^ block1[1];
        rk[4 * (2 * i + 1) + 6] = block2[2];
        block2[2] = tmp[2] ^ block1[2];
        rk[4 * (2 * i + 1) + 7] = block2[3];
        block2[3] = tmp[3] ^ block1[3];

        rk[4 * (2 * i + 1)] = block1[0];
        block1[0] = tmp[0];
        rk[4 * (2 * i + 1) + 1] = block1[1];
        block1[1] = tmp[1];
        rk[4 * (2 * i + 1) + 2] = block1[2];
        block1[2] = tmp[2];
        rk[4 * (2 * i + 1) + 3] = block1[3];
        block1[3] = tmp[3];
    }

    println!("-- set_encrypt_key - rk = {:02X?}", rk);
}

fn inv_key(input: u32) -> u32 {
    let tmp: u32 = MKV128_L4[((input >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((input >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((input >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(input & 0xFF) as usize] >> 24);

    return MKV128_IL0[((tmp >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((tmp >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((tmp >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(tmp & 0xFF) as usize];
}

fn set_decrypt_key(rounds: usize, key: &[u8], inv_rk: &mut [u32]) {
    let rk: &mut [u32] = &mut [0u32; 68];

    set_encrypt_key(rounds, key, rk);

    println!("-- set_decrypt_key - rk = {:02X?}", rk);
    println!("-- set_decrypt_key - inv_rk = {:02X?}", inv_rk);

    for i in 0..((2 * rounds + 1) * 4) {
        inv_rk[i] = rk[i];
    }
    println!("-- set_decrypt_key - inv_rk = {:02X?}", inv_rk);

    let mut i = 1;
    while i < (2 * rounds) {
        println!("-- set_decrypt_key - i = {}", i);
        inv_rk[4 * i] = inv_key(rk[4 * i]);
        inv_rk[4 * i + 1] = inv_key(rk[4 * i + 1]);
        inv_rk[4 * i + 2] = inv_key(rk[4 * i + 2]);
        inv_rk[4 * i + 3] = inv_key(rk[4 * i + 3]);
        println!("-- set_decrypt_key - 4 * i + 3 = {}", 4 * i + 3);
        i = i + 2;
    }

    println!("-- set_decrypt_key end - i = {}", i);

    println!("-- set_decrypt_key - inv_rk = {:02X?}", inv_rk);

    println!("8-- set_decrypt_key - inv_rk = {:02X?}", inv_rk);
}

fn encrypt_32bit(rounds: usize, input: &[u8], out: &mut [u8], rk: &[u32]) {
    let (mut s0, mut s1, mut s2, mut s3): (u32, u32, u32, u32) = (0, 0, 0, 0);
    let (mut t0, mut t1, mut t2, mut t3): (u32, u32, u32, u32) = (0, 0, 0, 0);

    println!("6.-- encrypt_32bit - input = {:02X?}", input);

    println!("1.-- encrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("1.-- encrypt_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    t0 = u32::from_be_bytes(input[0..4].try_into().unwrap()) ^ rk[0];
    t1 = u32::from_be_bytes(input[4..8].try_into().unwrap()) ^ rk[1];
    t2 = u32::from_be_bytes(input[8..12].try_into().unwrap()) ^ rk[2];
    t3 = u32::from_be_bytes(input[12..16].try_into().unwrap()) ^ rk[3];

    println!("2.-- encrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("2.-- encrypt_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    s0 = MKV128_L0[((t0 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t0 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t0 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t0 & 0xFF) as usize]
        ^ rk[4];
    s1 = MKV128_L0[((t1 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t1 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t1 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t1 & 0xFF) as usize]
        ^ rk[5];
    s2 = MKV128_L0[((t2 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t2 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t2 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t2 & 0xFF) as usize]
        ^ rk[6];
    s3 = MKV128_L0[((t3 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t3 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t3 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t3 & 0xFF) as usize]
        ^ rk[7];

    t0 = MKV128_L4[((s0 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s0 & 0xFF) as usize] >> 24);
    t1 = MKV128_L4[((s1 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s1 & 0xFF) as usize] >> 24);
    t2 = MKV128_L4[((s2 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s2 & 0xFF) as usize] >> 24);
    t3 = MKV128_L4[((s3 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s3 & 0xFF) as usize] >> 24);

    s0 = t1 ^ t2 ^ t3 ^ rk[8];
    s1 = t0 ^ t2 ^ t3 ^ rk[9];
    s2 = t0 ^ t1 ^ t3 ^ rk[10];
    s3 = t0 ^ t1 ^ t2 ^ rk[11];

    t0 = MKV128_L0[((s0 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s0 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s0 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s0 & 0xFF) as usize]
        ^ rk[12];
    t1 = MKV128_L0[((s1 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s1 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s1 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s1 & 0xFF) as usize]
        ^ rk[13];
    t2 = MKV128_L0[((s2 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s2 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s2 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s2 & 0xFF) as usize]
        ^ rk[14];
    t3 = MKV128_L0[((s3 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s3 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s3 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s3 & 0xFF) as usize]
        ^ rk[15];

    s0 = MKV128_L4[((t0 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t0 & 0xFF) as usize] >> 24);
    s1 = MKV128_L4[((t1 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t1 & 0xFF) as usize] >> 24);
    s2 = MKV128_L4[((t2 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t2 & 0xFF) as usize] >> 24);
    s3 = MKV128_L4[((t3 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t3 & 0xFF) as usize] >> 24);

    t0 = s1 ^ s2 ^ s3 ^ rk[16];
    t1 = s0 ^ s2 ^ s3 ^ rk[17];
    t2 = s0 ^ s1 ^ s3 ^ rk[18];
    t3 = s0 ^ s1 ^ s2 ^ rk[19];

    s0 = MKV128_L0[((t0 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t0 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t0 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t0 & 0xFF) as usize]
        ^ rk[20];
    s1 = MKV128_L0[((t1 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t1 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t1 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t1 & 0xFF) as usize]
        ^ rk[21];
    s2 = MKV128_L0[((t2 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t2 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t2 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t2 & 0xFF) as usize]
        ^ rk[22];
    s3 = MKV128_L0[((t3 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t3 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t3 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t3 & 0xFF) as usize]
        ^ rk[23];

    t0 = MKV128_L4[((s0 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s0 & 0xFF) as usize] >> 24);
    t1 = MKV128_L4[((s1 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s1 & 0xFF) as usize] >> 24);
    t2 = MKV128_L4[((s2 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s2 & 0xFF) as usize] >> 24);
    t3 = MKV128_L4[((s3 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s3 & 0xFF) as usize] >> 24);

    s0 = t1 ^ t2 ^ t3 ^ rk[24];
    s1 = t0 ^ t2 ^ t3 ^ rk[25];
    s2 = t0 ^ t1 ^ t3 ^ rk[26];
    s3 = t0 ^ t1 ^ t2 ^ rk[27];

    t0 = MKV128_L0[((s0 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s0 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s0 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s0 & 0xFF) as usize]
        ^ rk[28];
    t1 = MKV128_L0[((s1 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s1 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s1 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s1 & 0xFF) as usize]
        ^ rk[29];
    t2 = MKV128_L0[((s2 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s2 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s2 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s2 & 0xFF) as usize]
        ^ rk[30];
    t3 = MKV128_L0[((s3 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s3 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s3 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s3 & 0xFF) as usize]
        ^ rk[31];

    s0 = MKV128_L4[((t0 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t0 & 0xFF) as usize] >> 24);
    s1 = MKV128_L4[((t1 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t1 & 0xFF) as usize] >> 24);
    s2 = MKV128_L4[((t2 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t2 & 0xFF) as usize] >> 24);
    s3 = MKV128_L4[((t3 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t3 & 0xFF) as usize] >> 24);

    t0 = s1 ^ s2 ^ s3 ^ rk[32];
    t1 = s0 ^ s2 ^ s3 ^ rk[33];
    t2 = s0 ^ s1 ^ s3 ^ rk[34];
    t3 = s0 ^ s1 ^ s2 ^ rk[35];

    s0 = MKV128_L0[((t0 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t0 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t0 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t0 & 0xFF) as usize]
        ^ rk[36];
    s1 = MKV128_L0[((t1 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t1 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t1 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t1 & 0xFF) as usize]
        ^ rk[37];
    s2 = MKV128_L0[((t2 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t2 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t2 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t2 & 0xFF) as usize]
        ^ rk[38];
    s3 = MKV128_L0[((t3 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((t3 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((t3 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(t3 & 0xFF) as usize]
        ^ rk[39];

    t0 = MKV128_L4[((s0 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s0 & 0xFF) as usize] >> 24);
    t1 = MKV128_L4[((s1 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s1 & 0xFF) as usize] >> 24);
    t2 = MKV128_L4[((s2 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s2 & 0xFF) as usize] >> 24);
    t3 = MKV128_L4[((s3 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((s3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((s3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(s3 & 0xFF) as usize] >> 24);

    s0 = t1 ^ t2 ^ t3 ^ rk[40];
    s1 = t0 ^ t2 ^ t3 ^ rk[41];
    s2 = t0 ^ t1 ^ t3 ^ rk[42];
    s3 = t0 ^ t1 ^ t2 ^ rk[43];

    t0 = MKV128_L0[((s0 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s0 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s0 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s0 & 0xFF) as usize]
        ^ rk[44];
    t1 = MKV128_L0[((s1 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s1 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s1 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s1 & 0xFF) as usize]
        ^ rk[45];
    t2 = MKV128_L0[((s2 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s2 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s2 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s2 & 0xFF) as usize]
        ^ rk[46];
    t3 = MKV128_L0[((s3 >> 24) & 0xFF) as usize]
        ^ MKV128_L1[((s3 >> 16) & 0xFF) as usize]
        ^ MKV128_L2[((s3 >> 8) & 0xFF) as usize]
        ^ MKV128_L3[(s3 & 0xFF) as usize]
        ^ rk[47];

    s0 = MKV128_L4[((t0 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t0 & 0xFF) as usize] >> 24);
    s1 = MKV128_L4[((t1 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t1 & 0xFF) as usize] >> 24);
    s2 = MKV128_L4[((t2 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t2 & 0xFF) as usize] >> 24);
    s3 = MKV128_L4[((t3 >> 24) & 0xFF) as usize]
        ^ (MKV128_L4[((t3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_L4[((t3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_L4[(t3 & 0xFF) as usize] >> 24);

    t0 = s1 ^ s2 ^ s3 ^ rk[48];
    t1 = s0 ^ s2 ^ s3 ^ rk[49];
    t2 = s0 ^ s1 ^ s3 ^ rk[50];
    t3 = s0 ^ s1 ^ s2 ^ rk[51];

    println!("3.-- encrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("3.-- encrypt_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    if rounds == MKV128_ROUNDS_128 {
        out[0..4].copy_from_slice(&t0.to_be_bytes());
        out[4..8].copy_from_slice(&t1.to_be_bytes());
        out[8..12].copy_from_slice(&t2.to_be_bytes());
        out[12..16].copy_from_slice(&t3.to_be_bytes());
    }

    println!("4.-- encrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("4.-- encrypt_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    if rounds >= MKV128_ROUNDS_192 {
        s0 = MKV128_L0[((t0 >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((t0 >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((t0 >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(t0 & 0xFF) as usize]
            ^ rk[52];
        s1 = MKV128_L0[((t1 >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((t1 >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((t1 >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(t1 & 0xFF) as usize]
            ^ rk[53];
        s2 = MKV128_L0[((t2 >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((t2 >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((t2 >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(t2 & 0xFF) as usize]
            ^ rk[54];
        s3 = MKV128_L0[((t3 >> 24) & 0xFF) as usize]
            ^ MKV128_L1[((t3 >> 16) & 0xFF) as usize]
            ^ MKV128_L2[((t3 >> 8) & 0xFF) as usize]
            ^ MKV128_L3[(t3 & 0xFF) as usize]
            ^ rk[55];

        t0 = MKV128_L4[((s0 >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((s0 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((s0 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(s0 & 0xFF) as usize] >> 24);
        t1 = MKV128_L4[((s1 >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((s1 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((s1 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(s1 & 0xFF) as usize] >> 24);
        t2 = MKV128_L4[((s2 >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((s2 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((s2 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(s2 & 0xFF) as usize] >> 24);
        t3 = MKV128_L4[((s3 >> 24) & 0xFF) as usize]
            ^ (MKV128_L4[((s3 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_L4[((s3 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_L4[(s3 & 0xFF) as usize] >> 24);

        s0 = t1 ^ t2 ^ t3 ^ rk[56];
        s1 = t0 ^ t2 ^ t3 ^ rk[57];
        s2 = t0 ^ t1 ^ t3 ^ rk[58];
        s3 = t0 ^ t1 ^ t2 ^ rk[59];

        println!("5.-- encrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
        println!("5.-- encrypt_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);


        out[0..4].copy_from_slice(&s0.to_be_bytes());
        out[4..8].copy_from_slice(&s1.to_be_bytes());
        out[8..12].copy_from_slice(&s2.to_be_bytes());
        out[12..16].copy_from_slice(&s3.to_be_bytes());

        if rounds == MKV128_ROUNDS_256 {


            println!("6.-- encrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
            println!("6.-- encrypt_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);


            t0 = MKV128_L0[((s0 >> 24) & 0xFF) as usize]
                ^ MKV128_L1[((s0 >> 16) & 0xFF) as usize]
                ^ MKV128_L2[((s0 >> 8) & 0xFF) as usize]
                ^ MKV128_L3[(s0 & 0xFF) as usize]
                ^ rk[60];
            t1 = MKV128_L0[((s1 >> 24) & 0xFF) as usize]
                ^ MKV128_L1[((s1 >> 16) & 0xFF) as usize]
                ^ MKV128_L2[((s1 >> 8) & 0xFF) as usize]
                ^ MKV128_L3[(s1 & 0xFF) as usize]
                ^ rk[61];
            t2 = MKV128_L0[((s2 >> 24) & 0xFF) as usize]
                ^ MKV128_L1[((s2 >> 16) & 0xFF) as usize]
                ^ MKV128_L2[((s2 >> 8) & 0xFF) as usize]
                ^ MKV128_L3[(s2 & 0xFF) as usize]
                ^ rk[62];
            t3 = MKV128_L0[((s3 >> 24) & 0xFF) as usize]
                ^ MKV128_L1[((s3 >> 16) & 0xFF) as usize]
                ^ MKV128_L2[((s3 >> 8) & 0xFF) as usize]
                ^ MKV128_L3[(s3 & 0xFF) as usize]
                ^ rk[63];

            s0 = MKV128_L4[((t0 >> 24) & 0xFF) as usize]
                ^ (MKV128_L4[((t0 >> 16) & 0xFF) as usize] >> 8)
                ^ (MKV128_L4[((t0 >> 8) & 0xFF) as usize] >> 16)
                ^ (MKV128_L4[(t0 & 0xFF) as usize] >> 24);
            s1 = MKV128_L4[((t1 >> 24) & 0xFF) as usize]
                ^ (MKV128_L4[((t1 >> 16) & 0xFF) as usize] >> 8)
                ^ (MKV128_L4[((t1 >> 8) & 0xFF) as usize] >> 16)
                ^ (MKV128_L4[(t1 & 0xFF) as usize] >> 24);
            s2 = MKV128_L4[((t2 >> 24) & 0xFF) as usize]
                ^ (MKV128_L4[((t2 >> 16) & 0xFF) as usize] >> 8)
                ^ (MKV128_L4[((t2 >> 8) & 0xFF) as usize] >> 16)
                ^ (MKV128_L4[(t2 & 0xFF) as usize] >> 24);
            s3 = MKV128_L4[((t3 >> 24) & 0xFF) as usize]
                ^ (MKV128_L4[((t3 >> 16) & 0xFF) as usize] >> 8)
                ^ (MKV128_L4[((t3 >> 8) & 0xFF) as usize] >> 16)
                ^ (MKV128_L4[(t3 & 0xFF) as usize] >> 24);

            t0 = s1 ^ s2 ^ s3 ^ rk[64];
            t1 = s0 ^ s2 ^ s3 ^ rk[65];
            t2 = s0 ^ s1 ^ s3 ^ rk[66];
            t3 = s0 ^ s1 ^ s2 ^ rk[67];

            out[0..4].copy_from_slice(&t0.to_be_bytes());
            out[4..8].copy_from_slice(&t1.to_be_bytes());
            out[8..12].copy_from_slice(&t2.to_be_bytes());
            out[12..16].copy_from_slice(&t3.to_be_bytes());
        }
    }

    println!("7.-- encrypt_32bit - out = {:02X?}", out);
}

fn decrypt_32bit(rounds: usize, input: &[u8], out: &mut [u8], rk: &[u32]) {
    let (mut s0, mut s1, mut s2, mut s3): (u32, u32, u32, u32) = (0, 0, 0, 0);
    let (mut t0, mut t1, mut t2, mut t3): (u32, u32, u32, u32) = (0, 0, 0, 0);

    println!("0.-- decrypt_32bit - input = {:02X?}", input);

    println!("1.-- decrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("1.-- encryptdecrypt_32bit_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    if rounds == MKV128_ROUNDS_256 {
        t0 = u32::from_be_bytes(input[0..4].try_into().unwrap()) ^ rk[64];
        t1 = u32::from_be_bytes(input[4..8].try_into().unwrap()) ^ rk[65];
        t2 = u32::from_be_bytes(input[8..12].try_into().unwrap()) ^ rk[66];
        t3 = u32::from_be_bytes(input[12..16].try_into().unwrap()) ^ rk[67];

        s0 = t1 ^ t2 ^ t3;
        s1 = t0 ^ t2 ^ t3;
        s2 = t0 ^ t1 ^ t3;
        s3 = t0 ^ t1 ^ t2;

        t0 = MKV128_IL0[((s0 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((s0 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((s0 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(s0 & 0xFF) as usize]
            ^ rk[60];
        t1 = MKV128_IL0[((s1 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((s1 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((s1 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(s1 & 0xFF) as usize]
            ^ rk[61];
        t2 = MKV128_IL0[((s2 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((s2 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((s2 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(s2 & 0xFF) as usize]
            ^ rk[62];
        t3 = MKV128_IL0[((s3 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((s3 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((s3 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(s3 & 0xFF) as usize]
            ^ rk[63];

        s0 = MKV128_IL4[((t0 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((t0 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((t0 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(t0 & 0xFF) as usize] >> 24)
            ^ rk[56];
        s1 = MKV128_IL4[((t1 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((t1 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((t1 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(t1 & 0xFF) as usize] >> 24)
            ^ rk[57];
        s2 = MKV128_IL4[((t2 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((t2 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((t2 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(t2 & 0xFF) as usize] >> 24)
            ^ rk[58];
        s3 = MKV128_IL4[((t3 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((t3 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((t3 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(t3 & 0xFF) as usize] >> 24)
            ^ rk[59];

        t0 = s1 ^ s2 ^ s3;
        t1 = s0 ^ s2 ^ s3;
        t2 = s0 ^ s1 ^ s3;
        t3 = s0 ^ s1 ^ s2;

        s0 = MKV128_IL0[((t0 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t0 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t0 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t0 & 0xFF) as usize]
            ^ rk[52];
        s1 = MKV128_IL0[((t1 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t1 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t1 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t1 & 0xFF) as usize]
            ^ rk[53];
        s2 = MKV128_IL0[((t2 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t2 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t2 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t2 & 0xFF) as usize]
            ^ rk[54];
        s3 = MKV128_IL0[((t3 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t3 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t3 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t3 & 0xFF) as usize]
            ^ rk[55];

        t0 = MKV128_IL4[((s0 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s0 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s0 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s0 & 0xFF) as usize] >> 24)
            ^ rk[48];
        t1 = MKV128_IL4[((s1 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s1 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s1 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s1 & 0xFF) as usize] >> 24)
            ^ rk[49];
        t2 = MKV128_IL4[((s2 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s2 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s2 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s2 & 0xFF) as usize] >> 24)
            ^ rk[50];
        t3 = MKV128_IL4[((s3 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s3 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s3 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s3 & 0xFF) as usize] >> 24)
            ^ rk[51];
    }


    println!("2.-- decrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("2.-- encryptdecrypt_32bit_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    if rounds == MKV128_ROUNDS_192 {
        s0 = u32::from_be_bytes(input[0..4].try_into().unwrap()) ^ rk[56];
        s1 = u32::from_be_bytes(input[4..8].try_into().unwrap()) ^ rk[57];
        s2 = u32::from_be_bytes(input[8..12].try_into().unwrap()) ^ rk[58];
        s3 = u32::from_be_bytes(input[12..16].try_into().unwrap()) ^ rk[59];

        t0 = s1 ^ s2 ^ s3;
        t1 = s0 ^ s2 ^ s3;
        t2 = s0 ^ s1 ^ s3;
        t3 = s0 ^ s1 ^ s2;

        s0 = MKV128_IL0[((t0 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t0 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t0 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t0 & 0xFF) as usize]
            ^ rk[52];
        s1 = MKV128_IL0[((t1 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t1 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t1 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t1 & 0xFF) as usize]
            ^ rk[53];
        s2 = MKV128_IL0[((t2 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t2 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t2 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t2 & 0xFF) as usize]
            ^ rk[54];
        s3 = MKV128_IL0[((t3 >> 24) & 0xFF) as usize]
            ^ MKV128_IL1[((t3 >> 16) & 0xFF) as usize]
            ^ MKV128_IL2[((t3 >> 8) & 0xFF) as usize]
            ^ MKV128_IL3[(t3 & 0xFF) as usize]
            ^ rk[55];

        t0 = MKV128_IL4[((s0 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s0 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s0 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s0 & 0xFF) as usize] >> 24)
            ^ rk[48];
        t1 = MKV128_IL4[((s1 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s1 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s1 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s1 & 0xFF) as usize] >> 24)
            ^ rk[49];
        t2 = MKV128_IL4[((s2 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s2 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s2 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s2 & 0xFF) as usize] >> 24)
            ^ rk[50];
        t3 = MKV128_IL4[((s3 >> 24) & 0xFF) as usize]
            ^ (MKV128_IL4[((s3 >> 16) & 0xFF) as usize] >> 8)
            ^ (MKV128_IL4[((s3 >> 8) & 0xFF) as usize] >> 16)
            ^ (MKV128_IL4[(s3 & 0xFF) as usize] >> 24)
            ^ rk[51];
    }

    println!("3.-- decrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("3.-- encryptdecrypt_32bit_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    if rounds == MKV128_ROUNDS_128 {
        t0 = u32::from_be_bytes(input[0..4].try_into().unwrap()) ^ rk[48];
        t1 = u32::from_be_bytes(input[4..8].try_into().unwrap()) ^ rk[49];
        t2 = u32::from_be_bytes(input[8..12].try_into().unwrap()) ^ rk[50];
        t3 = u32::from_be_bytes(input[12..16].try_into().unwrap()) ^ rk[51];
    }



    println!("4.-- decrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("4.-- encryptdecrypt_32bit_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    s0 = t1 ^ t2 ^ t3;
    s1 = t0 ^ t2 ^ t3;
    s2 = t0 ^ t1 ^ t3;
    s3 = t0 ^ t1 ^ t2;

    t0 = MKV128_IL0[((s0 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s0 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s0 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s0 & 0xFF) as usize]
        ^ rk[44];
    t1 = MKV128_IL0[((s1 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s1 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s1 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s1 & 0xFF) as usize]
        ^ rk[45];
    t2 = MKV128_IL0[((s2 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s2 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s2 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s2 & 0xFF) as usize]
        ^ rk[46];
    t3 = MKV128_IL0[((s3 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s3 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s3 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s3 & 0xFF) as usize]
        ^ rk[47];

    s0 = MKV128_IL4[((t0 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t0 & 0xFF) as usize] >> 24)
        ^ rk[40];
    s1 = MKV128_IL4[((t1 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t1 & 0xFF) as usize] >> 24)
        ^ rk[41];
    s2 = MKV128_IL4[((t2 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t2 & 0xFF) as usize] >> 24)
        ^ rk[42];
    s3 = MKV128_IL4[((t3 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t3 & 0xFF) as usize] >> 24)
        ^ rk[43];

    t0 = s1 ^ s2 ^ s3;
    t1 = s0 ^ s2 ^ s3;
    t2 = s0 ^ s1 ^ s3;
    t3 = s0 ^ s1 ^ s2;

    s0 = MKV128_IL0[((t0 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t0 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t0 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t0 & 0xFF) as usize]
        ^ rk[36];
    s1 = MKV128_IL0[((t1 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t1 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t1 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t1 & 0xFF) as usize]
        ^ rk[37];
    s2 = MKV128_IL0[((t2 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t2 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t2 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t2 & 0xFF) as usize]
        ^ rk[38];
    s3 = MKV128_IL0[((t3 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t3 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t3 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t3 & 0xFF) as usize]
        ^ rk[39];

    t0 = MKV128_IL4[((s0 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s0 & 0xFF) as usize] >> 24)
        ^ rk[32];
    t1 = MKV128_IL4[((s1 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s1 & 0xFF) as usize] >> 24)
        ^ rk[33];
    t2 = MKV128_IL4[((s2 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s2 & 0xFF) as usize] >> 24)
        ^ rk[34];
    t3 = MKV128_IL4[((s3 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s3 & 0xFF) as usize] >> 24)
        ^ rk[35];

    s0 = t1 ^ t2 ^ t3;
    s1 = t0 ^ t2 ^ t3;
    s2 = t0 ^ t1 ^ t3;
    s3 = t0 ^ t1 ^ t2;

    t0 = MKV128_IL0[((s0 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s0 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s0 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s0 & 0xFF) as usize]
        ^ rk[28];
    t1 = MKV128_IL0[((s1 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s1 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s1 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s1 & 0xFF) as usize]
        ^ rk[29];
    t2 = MKV128_IL0[((s2 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s2 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s2 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s2 & 0xFF) as usize]
        ^ rk[30];
    t3 = MKV128_IL0[((s3 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s3 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s3 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s3 & 0xFF) as usize]
        ^ rk[31];

    s0 = MKV128_IL4[((t0 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t0 & 0xFF) as usize] >> 24)
        ^ rk[24];
    s1 = MKV128_IL4[((t1 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t1 & 0xFF) as usize] >> 24)
        ^ rk[25];
    s2 = MKV128_IL4[((t2 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t2 & 0xFF) as usize] >> 24)
        ^ rk[26];
    s3 = MKV128_IL4[((t3 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t3 & 0xFF) as usize] >> 24)
        ^ rk[27];

    t0 = s1 ^ s2 ^ s3;
    t1 = s0 ^ s2 ^ s3;
    t2 = s0 ^ s1 ^ s3;
    t3 = s0 ^ s1 ^ s2;

    s0 = MKV128_IL0[((t0 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t0 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t0 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t0 & 0xFF) as usize]
        ^ rk[20];
    s1 = MKV128_IL0[((t1 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t1 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t1 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t1 & 0xFF) as usize]
        ^ rk[21];
    s2 = MKV128_IL0[((t2 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t2 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t2 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t2 & 0xFF) as usize]
        ^ rk[22];
    s3 = MKV128_IL0[((t3 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t3 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t3 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t3 & 0xFF) as usize]
        ^ rk[23];

    t0 = MKV128_IL4[((s0 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s0 & 0xFF) as usize] >> 24)
        ^ rk[16];
    t1 = MKV128_IL4[((s1 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s1 & 0xFF) as usize] >> 24)
        ^ rk[17];
    t2 = MKV128_IL4[((s2 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s2 & 0xFF) as usize] >> 24)
        ^ rk[18];
    t3 = MKV128_IL4[((s3 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s3 & 0xFF) as usize] >> 24)
        ^ rk[19];

    s0 = t1 ^ t2 ^ t3;
    s1 = t0 ^ t2 ^ t3;
    s2 = t0 ^ t1 ^ t3;
    s3 = t0 ^ t1 ^ t2;

    t0 = MKV128_IL0[((s0 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s0 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s0 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s0 & 0xFF) as usize]
        ^ rk[12];
    t1 = MKV128_IL0[((s1 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s1 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s1 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s1 & 0xFF) as usize]
        ^ rk[13];
    t2 = MKV128_IL0[((s2 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s2 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s2 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s2 & 0xFF) as usize]
        ^ rk[14];
    t3 = MKV128_IL0[((s3 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((s3 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((s3 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(s3 & 0xFF) as usize]
        ^ rk[15];

    s0 = MKV128_IL4[((t0 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t0 & 0xFF) as usize] >> 24)
        ^ rk[8];
    s1 = MKV128_IL4[((t1 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t1 & 0xFF) as usize] >> 24)
        ^ rk[9];
    s2 = MKV128_IL4[((t2 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t2 & 0xFF) as usize] >> 24)
        ^ rk[10];
    s3 = MKV128_IL4[((t3 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((t3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((t3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(t3 & 0xFF) as usize] >> 24)
        ^ rk[11];

    t0 = s1 ^ s2 ^ s3;
    t1 = s0 ^ s2 ^ s3;
    t2 = s0 ^ s1 ^ s3;
    t3 = s0 ^ s1 ^ s2;

    s0 = MKV128_IL0[((t0 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t0 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t0 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t0 & 0xFF) as usize]
        ^ rk[4];
    s1 = MKV128_IL0[((t1 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t1 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t1 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t1 & 0xFF) as usize]
        ^ rk[5];
    s2 = MKV128_IL0[((t2 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t2 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t2 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t2 & 0xFF) as usize]
        ^ rk[6];
    s3 = MKV128_IL0[((t3 >> 24) & 0xFF) as usize]
        ^ MKV128_IL1[((t3 >> 16) & 0xFF) as usize]
        ^ MKV128_IL2[((t3 >> 8) & 0xFF) as usize]
        ^ MKV128_IL3[(t3 & 0xFF) as usize]
        ^ rk[7];

    t0 = MKV128_IL4[((s0 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s0 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s0 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s0 & 0xFF) as usize] >> 24)
        ^ rk[0];
    t1 = MKV128_IL4[((s1 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s1 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s1 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s1 & 0xFF) as usize] >> 24)
        ^ rk[1];
    t2 = MKV128_IL4[((s2 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s2 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s2 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s2 & 0xFF) as usize] >> 24)
        ^ rk[2];
    t3 = MKV128_IL4[((s3 >> 24) & 0xFF) as usize]
        ^ (MKV128_IL4[((s3 >> 16) & 0xFF) as usize] >> 8)
        ^ (MKV128_IL4[((s3 >> 8) & 0xFF) as usize] >> 16)
        ^ (MKV128_IL4[(s3 & 0xFF) as usize] >> 24)
        ^ rk[3];



    println!("5.-- decrypt_32bit - t0..t3 = {:02X?} {:02X?} {:02X?} {:02X?}", t0, t1, t2, t3);
    println!("5.-- encryptdecrypt_32bit_32bit - s0..s3 = {:02X?} {:02X?} {:02X?} {:02X?}", s0, s1, s2, s3);

    out[0..4].copy_from_slice(&t0.to_be_bytes());
    out[4..8].copy_from_slice(&t1.to_be_bytes());
    out[8..12].copy_from_slice(&t2.to_be_bytes());
    out[12..16].copy_from_slice(&t3.to_be_bytes());
}

fn get_rounds_by_subkey_size(subkey_size: usize) -> usize {
    let rd: usize;
    if subkey_size == 52 {
        rd = MKV128_ROUNDS_128;
    } else if subkey_size == 60 {
        rd = MKV128_ROUNDS_192;
    } else if subkey_size == 68 {
        rd = MKV128_ROUNDS_256;
    } else {
        rd = 0;
    }
    return rd;
}

macro_rules! impl_mkv128 {
    ($name:ident, $subkey_size:literal, $key_size:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            ek: [u32; $subkey_size],
            dk: [u32; $subkey_size],
        }

        impl KeyInit for $name {
            fn new(key: &Key<Self>) -> Self {

                let r = get_rounds_by_subkey_size($subkey_size);

                let mut mkv128 = Self {
                    ek: [0u32; $subkey_size],
                    dk: [0u32; $subkey_size],
                };

                set_encrypt_key(r, key, &mut mkv128.ek);
                set_decrypt_key(r, key, &mut mkv128.dk);

                mkv128
            }
        }

        impl BlockCipher for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl Drop for $name {
            fn drop(&mut self) {
                self.ek.zeroize();
                self.dk.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $name {}

        cipher::impl_simple_block_encdec!(
            $name, U16, cipher, block,
            encrypt: {
                let rounds = get_rounds_by_subkey_size($subkey_size);
                let input = block.get_in();
                let output: &mut [u8] = &mut [0u8; 16];
                encrypt_32bit(rounds, input, output, &cipher.ek);
                block.get_out()[0..16].copy_from_slice(&output[0..16]);
                println!("10.-- encrypt - cipher.ek = {:02X?}", cipher.ek);
            }
            decrypt: {
                let rounds = get_rounds_by_subkey_size($subkey_size);
                let input = block.get_in();
                let output: &mut [u8] = &mut [0u8; 16];
                decrypt_32bit(rounds, input, output, &cipher.dk);
                block.get_out()[0..16].copy_from_slice(&output[0..16]);
                println!("10.-- encrypt - cipher.dk = {:02X?}", cipher.dk);
            }
        );
    };
}

impl_mkv128!(Mkv128128, 52, U16, "Mkv128-128 block cipher instance.");
impl_mkv128!(Mkv128192, 60, U24, "Mkv128-192 block cipher instance.");
impl_mkv128!(Mkv128256, 68, U32, "Mkv128-256 block cipher instance.");
