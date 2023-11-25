use crate::kem;
use crate::kem::{KeyKind, KeyPair, KeyType, PublicKey, SecretKey};

pub type KyberLongTermKeyPair = KeyPair;
pub type KyberLongTermKeyPublic = PublicKey;
pub type KyberLongTermKeySecret = SecretKey;
pub const KYBER_LONG_TERM_KEY_TYPE: KeyType = KeyType::Kyber1024;

pub fn get_public_key_length() -> usize {
    kem::Public::key_length(KYBER_LONG_TERM_KEY_TYPE)
}

pub fn get_secret_key_length() -> usize {
    kem::Secret::key_length(KYBER_LONG_TERM_KEY_TYPE)
}
