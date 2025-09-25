use libc::{c_uchar, c_uint, size_t};

use kestrel_crypto::scrypt as ktl_scrypt;

/// Derives a secret key from a password and a salt using scrypt.
/// Recommended parameters are n = 32768, r = 8, p = 1
/// Parameter n must be larger than 1 and a power of 2
/// # Safety
/// The supplied lengths must be correct for their respective pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scrypt(
    password: *const c_uchar,
    password_len: size_t,
    salt: *const c_uchar,
    salt_len: size_t,
    n: c_uint,
    r: c_uint,
    p: c_uint,
    derived_key: *mut c_uchar,
    dk_len: size_t,
) {
    unsafe {
        let kpass = std::slice::from_raw_parts(password, password_len);

        let ksalt = std::slice::from_raw_parts(salt, salt_len);

        let kderived_key = std::slice::from_raw_parts_mut(derived_key, dk_len);

        let dk = ktl_scrypt(kpass, ksalt, n, r, p, kderived_key.len());

        kderived_key.copy_from_slice(dk.as_slice());
    }
}
