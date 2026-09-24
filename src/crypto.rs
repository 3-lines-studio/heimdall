use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key as CipherKey, XChaCha20Poly1305, XNonce};

const NONCE: usize = 24;

#[derive(Clone)]
pub struct Key([u8; 32]);

impl Key {
    pub fn from_hex(text: &str) -> Result<Key, String> {
        let bytes = decode_hex(text)?;
        if bytes.len() != 32 {
            return Err(format!(
                "la master key tiene {} bytes, espera 32",
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Key(key))
    }

    pub fn derive(&self, context: &str) -> Key {
        Key(blake3::derive_key(context, &self.0))
    }

    pub fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(&self.0));
        let mut nonce = [0u8; NONCE];
        getrandom::getrandom(&mut nonce).map_err(|e| format!("no hay azar: {e}"))?;
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), plain)
            .map_err(|_| "no pude cifrar".to_string())?;
        let mut blob = Vec::with_capacity(NONCE + sealed.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&sealed);
        Ok(blob)
    }

    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() <= NONCE {
            return Err("el archivo cifrado está cortado".to_string());
        }
        let cipher = XChaCha20Poly1305::new(CipherKey::from_slice(&self.0));
        cipher
            .decrypt(XNonce::from_slice(&blob[..NONCE]), &blob[NONCE..])
            .map_err(|_| "no pude descifrar: ¿cambió la master key?".to_string())
    }
}

pub fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("no hay azar: {e}"))?;
    Ok(encode_hex(&buf))
}

pub fn hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

pub fn equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("el hexadecimal tiene largo impar".to_string());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| "no es hexadecimal")?;
        let byte = u8::from_str_radix(pair, 16).map_err(|_| "no es hexadecimal")?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_hex(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn seal_and_open_round_trip() {
        let blob = key().seal(b"secreto").unwrap();
        assert_eq!(key().open(&blob).unwrap(), b"secreto");
        assert!(!blob.windows(7).any(|w| w == b"secreto"));
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        assert_ne!(key().seal(b"x").unwrap(), key().seal(b"x").unwrap());
    }

    #[test]
    fn another_key_does_not_open() {
        let blob = key().seal(b"secreto").unwrap();
        let other = Key::from_hex(&"cd".repeat(32)).unwrap();
        assert!(other.open(&blob).is_err());
    }

    #[test]
    fn a_context_does_not_open_another() {
        let key = key();
        let blob = key.derive("proyecto/a").seal(b"x").unwrap();
        assert_eq!(key.derive("proyecto/a").open(&blob).unwrap(), b"x");
        assert!(key.derive("proyecto/b").open(&blob).is_err());
    }

    #[test]
    fn truncated_blobs_do_not_open() {
        assert!(key().open(b"corto").is_err());
    }

    #[test]
    fn master_key_is_32_bytes_of_hex() {
        assert!(Key::from_hex("ab").is_err());
        assert!(Key::from_hex(&"zz".repeat(32)).is_err());
        assert!(Key::from_hex(&"ab".repeat(32)).is_ok());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(
            decode_hex(&encode_hex(&[0, 15, 255])).unwrap(),
            vec![0, 15, 255]
        );
    }

    #[test]
    fn equal_is_length_aware() {
        assert!(equal("abc", "abc"));
        assert!(!equal("abc", "abd"));
        assert!(!equal("abc", "ab"));
    }
}
