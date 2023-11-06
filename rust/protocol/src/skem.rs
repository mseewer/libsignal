mod frodokexp;

use crate::{Result, SignalProtocolError};

use displaydoc::Display;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ops::Deref;
use subtle::ConstantTimeEq;

type SharedSecret = Box<[u8]>;
type Seed = Box<[u8]>;
type Matrix = Box<[i32]>;
type Tag = Box<[u8]>;
// The difference between the two is that the raw one does not contain the KeyType byte prefix.
pub(crate) type RawCiphertext = Box<[u8]>;
pub type SerializedCiphertext = Box<[u8]>;


pub struct PublicParameters {
    seed: Seed,
    store_matrix: bool,
    public_matrix: Option<Matrix>,
    public_matrix_transpose: Option<Matrix>,
}

impl PublicParameters {
    pub fn generate(key_type: KeyType, store_matrix: bool) -> Self{
        key_type.parameters().generate_public_parameters(store_matrix)
    }
}


/// Each KEM supported by libsignal-protocol implements this trait.
///
/// Similar to the traits in RustCrypto's [kem](https://docs.rs/kem/) crate.
///
/// # Example
/// ```ignore
/// struct MyNiftyKEM;
/// # #[cfg(ignore_even_when_running_all_tests)]
/// impl Parameters for MyNiftyKEM {
///     // ...
/// }
/// ```
trait Parameters {
    const PUBLIC_PARAMETER_MATRIX_SIZE_BYTES: usize;
    const PUBLIC_KEY_P_MATRIX_SIZE_BYTES: usize;
    const SECRET_KEY_S_MATRIX_SIZE_BYTES: usize;
    const SECRET_KEY_F_SIZE_BYTES: usize;
    const CIPHERTEXT_SIZE_BYTES: usize;
    const SHARED_SECRET_SIZE_BYTES: usize;
    const TAG_SIZE_BYTES: usize;

    fn generate_public_parameters(store_matrix: bool) -> PublicParameters;
    fn generate_encapsulator(pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn generate_decapsulator(pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn encapsulate(my_sec_key: &SecretKeyMaterial, my_pub_key: &PublicKeyMaterial, other_pub_key: &PublicKeyMaterial) -> (SharedSecret, RawCiphertext, Tag);
    fn decapsulate(my_sec_key: &SecretKeyMaterial, my_pub_key: &PublicKeyMaterial, other_pub_key: &PublicKeyMaterial, ciphertext: &[u8], tag: &[u8]) -> Result<SharedSecret>;
}

/// Acts as a bridge between the static [Parameters] trait and the dynamic [KeyType] enum.
trait DynParameters {
    fn public_parameter_matrix_length(&self) -> usize;
    fn public_key_p_matrix_length(&self) -> usize;
    fn secret_key_s_matrix_length(&self) -> usize;
    fn secret_key_f_matrix_length(&self) -> usize;
    fn shared_secret_length(&self) -> usize;
    fn ciphertext_length(&self) -> usize;

    fn generate_public_parameters(&self, store_matrix: bool) -> PublicParameters;
    fn generate_encapsulator(&self, pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn generate_decapsulator(&self, pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn encapsulate(&self, my_sec_key: &SecretKeyMaterial, my_pub_key: &PublicKeyMaterial, other_pub_key: &PublicKeyMaterial) -> (SharedSecret, RawCiphertext, Tag);
    fn decapsulate(
        &self,
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<SharedSecret>;
}

impl<T: Parameters> DynParameters for T {
    fn public_parameter_matrix_length(&self) -> usize {
        Self::PUBLIC_PARAMETER_MATRIX_SIZE_BYTES
    }

    fn public_key_p_matrix_length(&self) -> usize {
        Self::PUBLIC_KEY_P_MATRIX_SIZE_BYTES
    }

    fn secret_key_s_matrix_length(&self) -> usize {
        Self::SECRET_KEY_S_MATRIX_SIZE_BYTES
    }

    fn secret_key_f_matrix_length(&self) -> usize {
        Self::SECRET_KEY_F_SIZE_BYTES
    }

    fn shared_secret_length(&self) -> usize {
        Self::SHARED_SECRET_SIZE_BYTES
    }

    fn ciphertext_length(&self) -> usize {
        Self::CIPHERTEXT_SIZE_BYTES
    }


    fn generate_public_parameters(&self, store_matrix: bool) -> PublicParameters {
        Self::generate_public_parameters(store_matrix)
    }

    fn generate_encapsulator(&self, pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial) {
        Self::generate_encapsulator(pp)
    }

    fn generate_decapsulator(&self, pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial) {
        Self::generate_decapsulator(pp)
    }

    fn encapsulate(&self, my_sec_key: &SecretKeyMaterial, my_pub_key: &PublicKeyMaterial, other_pub_key: &PublicKeyMaterial) -> (SharedSecret, RawCiphertext, Tag) {
        Self::encapsulate(my_sec_key, my_pub_key, other_pub_key)
    }

    fn decapsulate(
        &self,
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial, 
        other_pub_key: &PublicKeyMaterial,
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<SharedSecret> {
        Self::decapsulate(my_sec_key, my_pub_key, other_pub_key, ciphertext, tag)
    }
}

/// Designates a supported KEM protocol
#[derive(Display, Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    /// Frodokexp
    Frodokexp,
}

impl KeyType {
    fn value(&self) -> u8 {
        match self {
            KeyType::Frodokexp => 0x11,
        }
    }

    /// Allows KeyType to act like `&dyn Parameters` while still being represented by a single byte.
    ///
    /// Declared `const` to encourage inlining.
    const fn parameters(&self) -> &'static dyn DynParameters {
        match self {
            KeyType::Frodokexp => &frodokexp::Parameters,
        }
    }
}

impl TryFrom<i32> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: i32) -> Result<Self> {
        match x {
            0x11 => Ok(KeyType::Frodokexp),
            t => Err(SignalProtocolError::BadSKEMKeyType(t)),
        }
    }
}


#[derive(Clone)]
pub struct PublicKeyMaterial {
    key_type: KeyType,
    p_mat: Key<Public>,
}

#[derive(Clone)]
pub struct SecretKeyMaterial {
    key_type: KeyType,
    s_mat: Key<Secret>,
    f_mat: Key<FSecret>,
}

pub trait KeyKind {
    fn key_length(key_type: KeyType) -> usize;
}

#[derive(Clone, Debug)]
pub struct Public;

impl KeyKind for Public {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().public_key_p_matrix_length()
    }
}

#[derive(Clone, Debug)]
pub struct Secret;

impl KeyKind for Secret {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().secret_key_s_matrix_length()
    }
}


#[derive(Clone, Debug)]
pub struct FSecret;

impl KeyKind for FSecret {
    fn key_length(key_type: KeyType) -> usize {
        key_type.parameters().secret_key_f_matrix_length()
    }
}


#[derive(Clone)]
pub(crate) struct KeyMaterial<T: KeyKind> {
    data: Box<[i32]>,
    kind: PhantomData<T>,
}

impl<T: KeyKind> KeyMaterial<T> {
    fn new(data: Box<[i32]>) -> Self {
        KeyMaterial {
            data,
            kind: PhantomData,
        }
    }
}

impl<T: KeyKind> Deref for KeyMaterial<T> {
    type Target = [i32];

    fn deref(&self) -> &Self::Target {
        self.data.deref()
    }
}

#[derive(Clone)]
pub struct Key<T: KeyKind> {
    key_type: KeyType,
    key_data: KeyMaterial<T>,
}


impl<T: KeyKind> Key<T> {
    /// Create a `Key<Kind>` instance from a byte string created with the
    /// function `Key<Kind>::serialize(&self)`.
    pub fn deserialize(value: &[i32]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        if value.len() != T::key_length(key_type) + 1 {
            return Err(SignalProtocolError::BadSKEMKeyLength(key_type, value.len()));
        }
        Ok(Key {
            key_type,
            key_data: KeyMaterial::new(value[1..].into()),
        })
    }
    /// Create a binary representation of the key that includes a protocol identifier.
    pub fn serialize(&self) -> Box<[i32]> {
        let mut result: Vec<i32> = Vec::with_capacity(1 + self.key_data.len());
        result.push(self.key_type.value() as i32);
        result.extend_from_slice(&self.key_data);
        result.into_boxed_slice()
    }

    /// Return the `KeyType` that identifies the SKEM protocol for this key.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

impl PublicKeyMaterial {
    /// Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the
    /// holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same
    /// `SharedSecret`.
    pub fn encapsulate(&self, my_pub_key: &PublicKeyMaterial, my_sec_key: &SecretKeyMaterial) -> (SharedSecret, SerializedCiphertext, Tag) {
        let (ss, ct, tag) = self.key_type.parameters().encapsulate(my_sec_key, my_pub_key, &self);
        (
            ss,
            // TODO: maybe simplify this
            Ciphertext {
                key_type: self.key_type,
                data: &ct,
            }
            .serialize(),
            tag,
        )
    }

    pub fn serialize(&self) -> Box<[i32]> {
        self.p_mat.serialize()
    }

    pub fn deserialize(p_mat_serialized: Box<[i32]>) -> Result<Self> {
        if p_mat_serialized.is_empty() {
            return  Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(p_mat_serialized[0])?;
        if p_mat_serialized.len() != Public::key_length(key_type) + 1 {
            return Err(SignalProtocolError::BadSKEMKeyLength(key_type, p_mat_serialized.len()));
        }
        let p_mat = Key::<Public>::deserialize(&p_mat_serialized)?;
        Ok(PublicKeyMaterial {
            key_type: key_type,
            p_mat: p_mat
        })
    }
}

impl SecretKeyMaterial {
    /// Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of
    /// the corresponding `PublicKeyMaterial`.
    pub fn decapsulate(&self, my_pub_key: &PublicKeyMaterial, other_pub_key: &PublicKeyMaterial, ct_bytes: &SerializedCiphertext, tag: &[u8], ) -> Result<SharedSecret> {
        // deserialization checks that the length is correct for the KeyType
        let ct = Ciphertext::deserialize(ct_bytes)?;
        if ct.key_type != self.key_type {
            return Err(SignalProtocolError::WrongSKEMKeyType(
                ct.key_type.value(),
                self.key_type.value(),
            ));
        }
        self.key_type
            .parameters()
            .decapsulate(&self, my_pub_key, other_pub_key, ct.data, tag)
    }

    pub fn serialize(&self) -> (Box<[i32]>, Box<[i32]>) {
        (self.s_mat.serialize(), self.f_mat.serialize())
    }

    pub fn deserialize(s_mat_serialized: Box<[i32]>, f_mat_serialized: Box<[i32]>) -> Result<Self> {
        if s_mat_serialized.is_empty() || f_mat_serialized.is_empty() {
            return  Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let s_key_type = KeyType::try_from(s_mat_serialized[0])?;
        let f_key_type = KeyType::try_from(f_mat_serialized[0])?;
        if s_mat_serialized.len() != Secret::key_length(s_key_type) + 1 {
            return Err(SignalProtocolError::BadSKEMKeyLength(s_key_type, s_mat_serialized.len()));
        }
        if f_mat_serialized.len() != FSecret::key_length(f_key_type) + 1 {
            return Err(SignalProtocolError::BadSKEMKeyLength(f_key_type, f_mat_serialized.len()));
        }
        if s_key_type != f_key_type {
            return Err(SignalProtocolError::MismatchSKEMSecretKeyMaterial(s_key_type, f_key_type));
        }
        let s_mat = Key::<Secret>::deserialize(&s_mat_serialized)?;
        let f_mat = Key::<FSecret>::deserialize(&f_mat_serialized)?;
        if s_mat.key_type != f_mat.key_type {
            return Err(SignalProtocolError::MismatchSKEMSecretKeyMaterial(s_mat.key_type, f_mat.key_type));
        }
        Ok(SecretKeyMaterial { 
            key_type: s_key_type,
            s_mat: s_mat,
            f_mat: f_mat
        })
    }
}

impl TryFrom<&[i32]> for Key<Public> {
    type Error = SignalProtocolError;

    fn try_from(value: &[i32]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl TryFrom<&[i32]> for Key<Secret> {
    type Error = SignalProtocolError;

    fn try_from(value: &[i32]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl TryFrom<&[i32]> for Key<FSecret> {
    type Error = SignalProtocolError;

    fn try_from(value: &[i32]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for Key<Public> {
    /// A constant-time comparison if two `Key<Public>` instances are equal.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.key_data.ct_eq(&other.key_data)
    }
}

impl PartialEq for Key<Public> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Key<Public> {}

/// A SKEM public key with the ability to encapsulate a shared secret.
pub type PublicKey = Key<Public>;

/// A SKEM secret key together with a FSecret key have the ability to decapsulate a shared secret.
pub type SecretKey = Key<Secret>;
pub type FSecretKey = Key<FSecret>;



/// A public/secret key pair for a SKEM protocol.
#[derive(Clone)]
pub struct KeyPair {
    pub public_key_mat: PublicKeyMaterial,
    pub secret_key_mat: SecretKeyMaterial,
}

impl KeyPair {


    /// Creates a public-secret key pair for a the frodokexp protocol. Uses system randomness
    pub fn generate_encapsulator(key_type: KeyType, pp: &PublicParameters) -> Self {
        let (pk, sk) = key_type.parameters().generate_encapsulator(&pp);
        Self {
            secret_key_mat: sk,
            public_key_mat: pk,
        }
    }

    pub fn generate_decapsulator(key_type: KeyType, pp: &PublicParameters) -> Self {
        let (pk, sk) = key_type.parameters().generate_decapsulator(&pp);
        Self {
            secret_key_mat: sk,
            public_key_mat: pk,
        }
    }

    pub fn new(public_key_material: PublicKeyMaterial, secret_key_material: SecretKeyMaterial) -> Self {
        assert_eq!(public_key_material.key_type, secret_key_material.key_type);
        Self {
            public_key_mat: public_key_material,
            secret_key_mat: secret_key_material,
        }
    }

    /// Deserialize public and secret key material that were serialized by `PublicKeyMaterial::serialize()`
    /// and `SecretKeyMaterial::serialize()` respectively.
    pub fn from_public_and_private(public_key: &[i32], secret_key: &[i32], f_key: &[i32]) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;
        let secret_key = SecretKey::try_from(secret_key)?;
        let f_key = FSecretKey::try_from(f_key)?;

        if public_key.key_type != secret_key.key_type || secret_key.key_type != f_key.key_type {
            Err(SignalProtocolError::WrongSKEMKeyType(
                secret_key.key_type.value(),
                public_key.key_type.value(),
            ))
        } else {
            Ok(Self {
                public_key_mat: PublicKeyMaterial {
                    key_type: public_key.key_type,
                    p_mat: public_key
                },
                secret_key_mat: SecretKeyMaterial {
                    key_type: secret_key.key_type,
                    s_mat: secret_key,
                    f_mat: f_key
                },
            })
        }
    }
}

/// Utility type to handle serialization and deserialization of ciphertext data
struct Ciphertext<'a> {
    key_type: KeyType,
    data: &'a [u8],
}

impl<'a> Ciphertext<'a> {
    /// Create a `Ciphertext` instance from a byte string created with the
    /// function `Ciphertext::serialize(&self)`.
    pub fn deserialize(value: &'a [u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0] as i32)?;
        if value.len() != key_type.parameters().ciphertext_length() + 1 {
            return Err(SignalProtocolError::BadSKEMCiphertextLength(
                key_type,
                value.len(),
            ));
        }
        Ok(Ciphertext {
            key_type,
            data: &value[1..],
        })
    }

    /// Create a binary representation of the key that includes a protocol identifier.
    pub fn serialize(&self) -> SerializedCiphertext {
        let mut result = Vec::with_capacity(1 + self.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(self.data);
        result.into_boxed_slice()
    }
}
