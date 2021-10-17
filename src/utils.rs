pub(crate) const PROLOGUE: [u8; 4] = [0x57, 0x52, 0x4e, 0x10];

pub(crate) const PASS_FILE_MAGIC: [u8; 4] = [0x57, 0x52, 0x4e, 0x30];

pub(crate) const CHUNK_SIZE: usize = 65536;

pub(crate) const SCRYPT_N: u32 = 32768;
pub(crate) const SCRYPT_R: u32 = 8;
pub(crate) const SCRYPT_P: u32 = 1;
