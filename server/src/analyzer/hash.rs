/// hash.rs — MD5 + SHA-1 + SHA-256 + SHA-512 sur buffer (étendu vs desktop).
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::types::Hashes;

pub fn compute(data: &[u8]) -> Hashes {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();

    // Chunks de 8 MB pour limiter la pression cache
    for chunk in data.chunks(8 * 1024 * 1024) {
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        sha512.update(chunk);
    }

    Hashes {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
        sha512: hex::encode(sha512.finalize()),
    }
}
