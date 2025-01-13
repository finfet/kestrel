// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

// Based off of the original Go implementation
//
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use orion::hazardous::kdf::pbkdf2::sha256 as pbkdf2;

// Copies n numbers from src into dst
fn block_copy(dst: &mut [u32], src: &[u32], n: usize) {
    dst[..n].copy_from_slice(&src[..n]);
}

// XORs numbers from dst with n numbers from src
fn block_xor(dst: &mut [u32], src: &[u32], n: usize) {
    for (i, elem) in src[..n].iter().enumerate() {
        dst[i] ^= elem;
    }
}

#[rustfmt::skip]
fn salsa_xor(tmp: &mut [u32], inn: &[u32], out: &mut [u32]) {
    let w0 = tmp[0] ^ inn[0];
    let w1 = tmp[1] ^ inn[1];
    let w2 = tmp[2] ^ inn[2];
    let w3 = tmp[3] ^ inn[3];
    let w4 = tmp[4] ^ inn[4];
    let w5 = tmp[5] ^ inn[5];
    let w6 = tmp[6] ^ inn[6];
    let w7 = tmp[7] ^ inn[7];
    let w8 = tmp[8] ^ inn[8];
    let w9 = tmp[9] ^ inn[9];
    let w10 = tmp[10] ^ inn[10];
    let w11 = tmp[11] ^ inn[11];
    let w12 = tmp[12] ^ inn[12];
    let w13 = tmp[13] ^ inn[13];
    let w14 = tmp[14] ^ inn[14];
    let w15 = tmp[15] ^ inn[15];

    let mut x0 = w0;
    let mut x1 = w1;
    let mut x2 = w2;
    let mut x3 = w3;
    let mut x4 = w4;
    let mut x5 = w5;
    let mut x6 = w6;
    let mut x7 = w7;
    let mut x8 = w8;
    let mut x9 = w9;
    let mut x10 = w10;
    let mut x11 = w11;
    let mut x12 = w12;
    let mut x13 = w13;
    let mut x14 = w14;
    let mut x15 = w15;

    for _ in (0..8).step_by(2) {
        x4 ^= x0.wrapping_add(x12).rotate_left(7);
		x8 ^= x4.wrapping_add(x0).rotate_left(9);
		x12 ^= x8.wrapping_add(x4).rotate_left(13);
		x0 ^= x12.wrapping_add(x8).rotate_left(18);

		x9 ^= x5.wrapping_add(x1).rotate_left(7);
		x13 ^= x9.wrapping_add(x5).rotate_left(9);
		x1 ^= x13.wrapping_add(x9).rotate_left(13);
		x5 ^= x1.wrapping_add(x13).rotate_left(18);

		x14 ^= x10.wrapping_add(x6).rotate_left(7);
		x2 ^= x14.wrapping_add(x10).rotate_left(9);
		x6 ^= x2.wrapping_add(x14).rotate_left(13);
		x10 ^= x6.wrapping_add(x2).rotate_left(18);

		x3 ^= x15.wrapping_add(x11).rotate_left(7);
		x7 ^= x3.wrapping_add(x15).rotate_left(9);
		x11 ^= x7.wrapping_add(x3).rotate_left(13);
		x15 ^= x11.wrapping_add(x7).rotate_left(18);

		x1 ^= x0.wrapping_add(x3).rotate_left(7);
		x2 ^= x1.wrapping_add(x0).rotate_left(9);
		x3 ^= x2.wrapping_add(x1).rotate_left(13);
		x0 ^= x3.wrapping_add(x2).rotate_left(18);

		x6 ^= x5.wrapping_add(x4).rotate_left(7);
		x7 ^= x6.wrapping_add(x5).rotate_left(9);
		x4 ^= x7.wrapping_add(x6).rotate_left(13);
		x5 ^= x4.wrapping_add(x7).rotate_left(18);

		x11 ^= x10.wrapping_add(x9).rotate_left(7);
		x8 ^= x11.wrapping_add(x10).rotate_left(9);
		x9 ^= x8.wrapping_add(x11).rotate_left(13);
		x10 ^= x9.wrapping_add(x8).rotate_left(18);

		x12 ^= x15.wrapping_add(x14).rotate_left(7);
		x13 ^= x12.wrapping_add(x15).rotate_left(9);
		x14 ^= x13.wrapping_add(x12).rotate_left(13);
		x15 ^= x14.wrapping_add(x13).rotate_left(18);
    }

    x0 = x0.wrapping_add(w0);
    x1 = x1.wrapping_add(w1);
    x2 = x2.wrapping_add(w2);
    x3 = x3.wrapping_add(w3);
    x4 = x4.wrapping_add(w4);
    x5 = x5.wrapping_add(w5);
    x6 = x6.wrapping_add(w6);
    x7 = x7.wrapping_add(w7);
    x8 = x8.wrapping_add(w8);
    x9 = x9.wrapping_add(w9);
    x10 = x10.wrapping_add(w10);
    x11 = x11.wrapping_add(w11);
    x12 = x12.wrapping_add(w12);
    x13 = x13.wrapping_add(w13);
    x14 = x14.wrapping_add(w14);
    x15 = x15.wrapping_add(w15);

    out[0] = x0; tmp[0] = x0;
    out[1] = x1; tmp[1] = x1;
    out[2] = x2; tmp[2] = x2;
    out[3] = x3; tmp[3] = x3;
    out[4] = x4; tmp[4] = x4;
    out[5] = x5; tmp[5] = x5;
    out[6] = x6; tmp[6] = x6;
    out[7] = x7; tmp[7] = x7;
    out[8] = x8; tmp[8] = x8;
    out[9] = x9; tmp[9] = x9;
    out[10] = x10; tmp[10] = x10;
    out[11] = x11; tmp[11] = x11;
    out[12] = x12; tmp[12] = x12;
    out[13] = x13; tmp[13] = x13;
    out[14] = x14; tmp[14] = x14;
    out[15] = x15; tmp[15] = x15;
}

#[rustfmt::skip]
fn block_mix(tmp: &mut [u32], inn: &[u32], out: &mut [u32], r: usize) {
    block_copy(tmp, &inn[(2*r-1)*16..], 16);
    for i in (0..2*r).step_by(2) {
        salsa_xor(tmp, &inn[i*16..], &mut out[i*8..]);
        salsa_xor(tmp, &inn[i*16+16..], &mut out[i*8+r*16..]);
    }
}

fn integer(b: &[u32], r: usize) -> u64 {
    let j = (2 * r - 1) * 16;
    u64::from(b[j]) | u64::from(b[j + 1]) << 32
}

#[allow(non_snake_case)]
fn smix(b: &mut [u8], r: usize, N: usize, v: &mut [u32], x: &mut [u32], y: &mut [u32]) {
    let mut tmp = [0u32; 16];
    let R = 32 * r;

    let mut j = 0;
    for i in 0..R {
        x[i] = u32::from_le_bytes(b[j..j + 4].try_into().unwrap());
        j += 4;
    }

    for i in (0..N as usize).step_by(2) {
        block_copy(&mut v[i * R..], x, R);
        block_mix(&mut tmp, x, y, r);

        block_copy(&mut v[(i + 1) * R..], y, R);
        block_mix(&mut tmp, y, x, r);
    }

    for _ in (0..N).step_by(2) {
        let j = (integer(x, r) & u64::from((N - 1) as u64)) as usize;
        block_xor(x, &v[j * R..], R);
        block_mix(&mut tmp, x, y, r);

        let j = (integer(y, r) & u64::from((N - 1) as u64)) as usize;
        block_xor(y, &v[j * R..], R);
        block_mix(&mut tmp, y, x, r);
    }

    let mut j = 0;
    for v in &x[..R] {
        b[j..j + 4].copy_from_slice(&v.to_le_bytes());
        j += 4;
    }
}

pub(crate) fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: usize,
    r: usize,
    p: usize,
    dk_len: usize,
) -> Vec<u8> {
    debug_assert!(usize::BITS >= 32);
    assert!(n > 1);
    assert!(n & (n - 1) == 0);
    assert!(r * p < 1 << 30);
    assert!(r <= usize::MAX / 128 / p);
    assert!(r <= usize::MAX / 256);
    assert!(n <= usize::MAX / 128 / r);

    let vlen: usize = 32 * n * r;
    let mut x = vec![0u32; 32 * r];
    let mut y = vec![0u32; 32 * r];
    let mut v = vec![0u32; vlen];
    let pass = pbkdf2::Password::from_slice(password).unwrap();
    let blen: usize = p * 128 * r;
    let mut b = vec![0u8; blen];
    pbkdf2::derive_key(&pass, salt, 1, &mut b).unwrap();

    for i in 0..p {
        smix(&mut b[i * 128 * r..], r, n, &mut v, &mut x, &mut y);
    }

    let mut dk = vec![0u8; dk_len];
    pbkdf2::derive_key(&pass, &b, 1, &mut dk).unwrap();

    dk
}

#[cfg(test)]
mod tests {
    use super::scrypt;

    #[test]
    fn test_scrypt_vectors() {
        let password = b"pleaseletmein";
        let salt = b"SodiumChloride";
        let want = hex::decode("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887").unwrap();
        let got = scrypt(password, salt, 16384, 8, 1, 64);
        assert_eq!(&want, &got);
    }
}
