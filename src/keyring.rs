use crate::crypto::{PrivateKey, PublicKey};

pub struct Key {
    name: String,
    public_key: PublicKey,
    private_key: Option<PrivateKey>,
}

impl Key {
    pub fn serialize(&self) -> Vec<u8> {
        // Public keys are hex strings with a 4 byte SHA256 checksum
        //
        // Private keys are pass encrypted base64 strings. Format big endian
        // [HEADER] - 20 bytes
        // 4 bytes  : WRN in ASCII + Version (0x20 hex) (0x57524E20)
        // 16 bytes : salt
        //
        // [Encrypted Plaintext] - (Overhead of 16)
        // 32 bytes : ciphertext of private key
        // 16 bytes : ciphertext tag
        todo!()
    }
}

// config is INI file with list of keys
/*
[Key]
Name = joe
PublicKey = 96f5ecf14bb50935eafed5266bc7da3cfd7f33ad09f8b1948d39b40e8df77ade30731249
PrivateKey = vhn4RD7+5QHWTBcWSz51/DRT3GdJ/uIhDzzEU5ZQFL03QLeGgLrhtZTH+zTimXI180iwC1H9/fg9c6gujeZ4XCK4nKlGudNL

[Key]
Name = Bobby Bobertson
PublicKey = 449c64b7fbe79b98979a219d7b262daf592a1ee7273ceb4dfb88a6044cac6ae3b83f0dd4
*/
