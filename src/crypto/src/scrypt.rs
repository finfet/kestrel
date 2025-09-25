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

// Applies Salsa20/8 to the XOR of 16 numbers from tmp and inn,
// and puts the result into both tmp and out.
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
#[allow(clippy::needless_range_loop)]
fn smix(b: &mut [u8], r: usize, N: usize, v: &mut [u32], x: &mut [u32], y: &mut [u32]) {
    let mut tmp = [0u32; 16];
    let R = 32 * r;

    let mut j = 0;
    for i in 0..R {
        x[i] = u32::from_le_bytes(b[j..j + 4].try_into().unwrap());
        j += 4;
    }

    for i in (0..N).step_by(2) {
        block_copy(&mut v[i * R..], x, R);
        block_mix(&mut tmp, x, y, r);

        block_copy(&mut v[(i + 1) * R..], y, R);
        block_mix(&mut tmp, y, x, r);
    }

    for _ in (0..N).step_by(2) {
        let j = (integer(x, r) & (N - 1) as u64) as usize;
        block_xor(x, &v[j * R..], R);
        block_mix(&mut tmp, x, y, r);

        let j = (integer(y, r) & (N - 1) as u64) as usize;
        block_xor(y, &v[j * R..], R);
        block_mix(&mut tmp, y, x, r);
    }

    let mut j = 0;
    for v in &x[..R] {
        b[j..j + 4].copy_from_slice(&v.to_le_bytes());
        j += 4;
    }
}

#[allow(clippy::assertions_on_constants)]
pub(crate) fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: usize,
    r: usize,
    p: usize,
    dk_len: usize,
) -> Vec<u8> {
    assert!(usize::BITS >= 32);
    assert!(n > 1);
    assert!(n & (n - 1) == 0);
    assert!(((r as u64) * (p as u64)) < 1 << 30);
    assert!(r <= (i32::MAX as usize) / 128 / p);
    assert!(r <= (i32::MAX as usize) / 256);
    assert!(n <= (i32::MAX as usize) / 128 / r);

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
    use ct_codecs::{Decoder, Hex};

    struct ScryptVector<'a> {
        password: &'a [u8],
        salt: &'a [u8],
        n: usize,
        r: usize,
        p: usize,
        expected_dk: &'a str,
        dk_len: usize,
    }

    static SCRYPT_VECTORS: [ScryptVector; 8] = [
        ScryptVector {
            password: b"password",
            salt: b"salt",
            n: 2,
            r: 10,
            p: 10,
            expected_dk: "482c858e229055e62f41e0ec819a5ee18bdb87251a534f75acd95ac5e50aa15f",
            dk_len: 32,
        },
        ScryptVector {
            password: b"password",
            salt: b"salt",
            n: 16,
            r: 100,
            p: 100,
            expected_dk: "88bd5edb52d1dd00188772ad36171290224e74829525b18d7323a57f91963c37",
            dk_len: 32,
        },
        ScryptVector {
            password: b"this is a long \x00 password",
            salt: b"and this is a long \x00 salt",
            n: 16384,
            r: 8,
            p: 1,
            expected_dk: "c3f182ee2dec846e70a6942fb529985a3a09765ef04c612923b17f18555a37076deb2b9830d69de5492651e4506ae5776d96d40f67aaee37e1777b8ad5c3111432bb3b6f7e1264401879e641ae",
            dk_len: 77,
        },
        ScryptVector {
            password: b"p",
            salt: b"s",
            n: 2,
            r: 1,
            p: 1,
            expected_dk: "48b0d2a8a3272611984c50ebd630af52",
            dk_len: 16,
        },
        ScryptVector {
            password: b"",
            salt: b"",
            n: 16,
            r: 1,
            p: 1,
            expected_dk: "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            dk_len: 64,
        },
        ScryptVector {
            password: b"password",
            salt: b"NaCl",
            n: 1024,
            r: 8,
            p: 16,
            expected_dk: "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            dk_len: 64,
        },
        ScryptVector {
            password: b"pleaseletmein",
            salt: b"SodiumChloride",
            n: 16384,
            r: 8,
            p: 1,
            expected_dk: "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            dk_len: 64,
        },
        // Test is disabled because it takes a long time to run
        ScryptVector {
            password: b"pleaseletmein",
            salt: b"SodiumChloride",
            n: 1048576,
            r: 8,
            p: 1,
            expected_dk: "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
            dk_len: 64,
        },
    ];

    #[test]
    fn test_scrypt_vectors() {
        for i in 0..SCRYPT_VECTORS.len() - 1 {
            let case = &SCRYPT_VECTORS[i];
            let got = scrypt(
                case.password,
                case.salt,
                case.n,
                case.r,
                case.p,
                case.dk_len,
            );
            let exp = Hex::decode_to_vec(case.expected_dk, None).unwrap();
            assert_eq!(exp.as_slice(), got.as_slice())
        }
    }
}
