mod frodokexp;

use crate::{Result, SignalProtocolError};

use displaydoc::Display;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ops::Deref;
use subtle::ConstantTimeEq;

type SharedSecret = Box<[u8]>;
pub type Seed = Box<[u8]>;
type Matrix = Box<[i32]>;
// The difference between the two is that the raw one does not contain the KeyType byte prefix.
pub(crate) type RawCiphertext = Box<[u8]>;
pub type SerializedCiphertext = Box<[u8]>;
pub(crate) type RawTag = Box<[u8]>;
pub type SerializedTag = Box<[u8]>;

#[derive(Clone)]
pub struct PublicParameters {
    seed: Seed,
    store_matrix: bool,
    public_matrix: Option<Matrix>,
    public_matrix_transpose: Option<Matrix>,
}

impl PublicParameters {
    pub fn generate(key_type: KeyType, store_matrix: bool) -> Self {
        key_type
            .parameters()
            .generate_public_parameters(store_matrix)
    }

    pub fn new(
        seed: Seed,
        store_matrix: bool,
        public_matrix: Option<Matrix>,
        public_matrix_transpose: Option<Matrix>,
    ) -> Self {
        Self {
            seed,
            store_matrix,
            public_matrix,
            public_matrix_transpose,
        }
    }

    pub fn from_seed(seed: Seed) -> Self {
        Self::new(seed, false, None, None)
    }
}

impl PublicParameters {
    pub fn get_seed(&self) -> &Seed {
        &self.seed
    }
}

/// Each KEM supported by libsignal-protocol implements this trait.
/// We do the same for our Split KEM (SKEM)
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
    const SEED_SIZE_BYTES: usize;

    fn generate_public_parameters(store_matrix: bool) -> PublicParameters;
    fn generate_encapsulator(pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn generate_decapsulator(pp: &PublicParameters) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn encapsulate(
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
    ) -> (SharedSecret, RawCiphertext, RawTag);
    fn decapsulate(
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<SharedSecret>;
}

/// Acts as a bridge between the static [Parameters] trait and the dynamic [KeyType] enum.
trait DynParameters {
    fn public_parameter_matrix_length(&self) -> usize;
    fn public_key_b_matrix_length(&self) -> usize;
    fn secret_key_s_matrix_length(&self) -> usize;
    fn secret_key_f_matrix_length(&self) -> usize;
    fn shared_secret_length(&self) -> usize;
    fn ciphertext_length(&self) -> usize;
    fn tag_length(&self) -> usize;
    fn seed_length(&self) -> usize;

    fn generate_public_parameters(&self, store_matrix: bool) -> PublicParameters;
    fn generate_encapsulator(
        &self,
        pp: &PublicParameters,
    ) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn generate_decapsulator(
        &self,
        pp: &PublicParameters,
    ) -> (PublicKeyMaterial, SecretKeyMaterial);
    fn encapsulate(
        &self,
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
    ) -> (SharedSecret, RawCiphertext, RawTag);
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

    fn public_key_b_matrix_length(&self) -> usize {
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

    fn tag_length(&self) -> usize {
        Self::TAG_SIZE_BYTES
    }

    fn seed_length(&self) -> usize {
        Self::SEED_SIZE_BYTES
    }

    fn generate_public_parameters(&self, store_matrix: bool) -> PublicParameters {
        Self::generate_public_parameters(store_matrix)
    }

    fn generate_encapsulator(
        &self,
        pp: &PublicParameters,
    ) -> (PublicKeyMaterial, SecretKeyMaterial) {
        Self::generate_encapsulator(pp)
    }

    fn generate_decapsulator(
        &self,
        pp: &PublicParameters,
    ) -> (PublicKeyMaterial, SecretKeyMaterial) {
        Self::generate_decapsulator(pp)
    }

    fn encapsulate(
        &self,
        my_sec_key: &SecretKeyMaterial,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
    ) -> (SharedSecret, RawCiphertext, RawTag) {
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

/// Designates a supported SKEM protocol
#[derive(Display, Debug, Copy, Clone, Eq)]
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

    pub const fn get_seed_length(&self) -> usize {
        match self {
            KeyType::Frodokexp => frodokexp::Parameters::SEED_SIZE_BYTES,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x11 => Ok(KeyType::Frodokexp),
            t => Err(SignalProtocolError::BadSKEMKeyType(t)),
        }
    }
}

/// A SKEM public key with the ability to encapsulate a shared secret.
/// The public part of the key
#[derive(Clone, Debug)]
pub struct PublicKeyMaterial {
    key_type: KeyType,
    b_mat: Key<Public>,
}

/// A SKEM secret key with the ability to decapsulate a shared secret.
/// The secret part of the key
#[derive(Clone, Debug)]
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
        key_type.parameters().public_key_b_matrix_length()
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

#[derive(Clone, Debug)]
pub(crate) struct KeyMaterial<T: KeyKind> {
    data: Box<[i32]>,
    kind: PhantomData<T>,
}

impl<T: KeyKind> KeyMaterial<T> {
    fn new_from_integers(data: Box<[i32]>) -> Self {
        KeyMaterial {
            data,
            kind: PhantomData,
        }
    }
    fn new(data: Box<[u8]>) -> Self {
        let integer_data = data
            .chunks_exact(4) // split in chunks of 4 since deserialize 4 u8's into one i32
            .map(|chunk| i32::from_le_bytes(chunk.try_into().expect("correct length")))
            .collect();

        KeyMaterial {
            data: integer_data,
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

#[derive(Clone, Debug)]
pub struct Key<T: KeyKind> {
    key_type: KeyType,
    key_data: KeyMaterial<T>,
}

impl<T: KeyKind> Key<T> {
    /// Create a `Key<Kind>` instance from a byte string created with the
    /// function `Key<Kind>::serialize(&self)`.
    pub fn deserialize(value: &[u8]) -> Result<Self> {
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
    pub fn serialize(&self) -> Box<[u8]> {
        // we need a capacity of 4 times the length since we need to serailze i32 to u8
        let mut result: Vec<u8> = Vec::with_capacity(1 + 4 * self.key_data.len());
        result.push(self.key_type.value());
        let bytes_representation = &self
            .key_data
            .iter()
            .map(|entry| entry.to_le_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        result.extend(bytes_representation);
        result.into_boxed_slice()
    }

    /// Return the `KeyType` that identifies the SKEM protocol for this key.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

impl PublicKeyMaterial {
    /// Create a `SharedSecret`,`Ciphertext` and a `Tag`. The `Ciphertext` and `Tag` can be
    /// safely sent to the holder of the corresponding `SecretKey` who can then use it to
    /// `decapsulate` the same SharedSecret`.
    pub fn encapsulate(
        &self,
        my_pub_key: &PublicKeyMaterial,
        my_sec_key: &SecretKeyMaterial,
    ) -> (SharedSecret, SerializedCiphertext, SerializedTag) {
        let (ss, ct, tag) = self
            .key_type
            .parameters()
            .encapsulate(my_sec_key, my_pub_key, &self);
        let serialized_ciphertext = Ciphertext {
            key_type: self.key_type,
            data: &ct,
        }
        .serialize();
        let serialized_tag = Tag {
            key_type: self.key_type,
            data: &tag,
        }
        .serialize();
        (ss, serialized_ciphertext, serialized_tag)
    }

    pub fn serialize(&self) -> Box<[u8]> {
        self.b_mat.serialize()
    }

    pub fn deserialize(b_mat_serialized: &[u8]) -> Result<Self> {
        if b_mat_serialized.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(b_mat_serialized[0])?;
        if b_mat_serialized.len() != Public::key_length(key_type) + 1 {
            return Err(SignalProtocolError::BadSKEMKeyLength(
                key_type,
                b_mat_serialized.len(),
            ));
        }
        let b_mat = Key::<Public>::deserialize(&b_mat_serialized)?;
        Ok(PublicKeyMaterial {
            key_type: key_type,
            b_mat,
        })
    }
}

impl From<&[u8]> for PublicKeyMaterial {
    fn from(key_serialized: &[u8]) -> Self {
        PublicKeyMaterial::deserialize(key_serialized)
            .expect("Input should be serialized Public Key")
    }
}

impl SecretKeyMaterial {
    /// Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` + `Tag` by a holder of
    /// the corresponding `PublicKeyMaterial`.
    pub fn decapsulate(
        &self,
        my_pub_key: &PublicKeyMaterial,
        other_pub_key: &PublicKeyMaterial,
        ct_bytes: &SerializedCiphertext,
        tag_bytes: &SerializedTag,
    ) -> Result<SharedSecret> {
        // deserialization checks that the length is correct for the KeyType
        let ct = Ciphertext::deserialize(ct_bytes)?;
        if ct.key_type != self.key_type {
            return Err(SignalProtocolError::WrongSKEMKeyType(
                ct.key_type.value(),
                self.key_type.value(),
            ));
        }
        // deserialization checks that the length is correct for the KeyType
        let tag = Tag::deserialize(tag_bytes)?;
        if tag.key_type != self.key_type {
            return Err(SignalProtocolError::WrongSKEMKeyType(
                tag.key_type.value(),
                self.key_type.value(),
            ));
        }
        self.key_type
            .parameters()
            .decapsulate(&self, my_pub_key, other_pub_key, ct.data, tag.data)
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let s_serialized = self.s_mat.serialize();
        let f_serialized = self.f_mat.serialize();
        [s_serialized, f_serialized].concat().into_boxed_slice()
    }

    // input just one box, need to check length
    pub fn deserialize(secret_key_mat_serialized: &[u8]) -> Result<Self> {
        if secret_key_mat_serialized.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let s_key_type = KeyType::try_from(secret_key_mat_serialized[0])?;
        if secret_key_mat_serialized.len() < Secret::key_length(s_key_type) + 1 + 2 {
            // minimum lengh: s_key_type length + 1 byte for type + 1 byte for f_key_type + at least 1 byte for f_key length (probably more!)
            return Err(SignalProtocolError::BadSKEMKeyLength(
                s_key_type,
                secret_key_mat_serialized.len(),
            ));
        }
        // + 1 in the length since we have the key type byte
        let s_mat_serialized = &secret_key_mat_serialized[..Secret::key_length(s_key_type) + 1];
        let f_mat_serialized = &secret_key_mat_serialized[Secret::key_length(s_key_type) + 1..];
        let f_key_type = KeyType::try_from(f_mat_serialized[0])?;
        if f_mat_serialized.len() != FSecret::key_length(f_key_type) + 1 {
            return Err(SignalProtocolError::BadSKEMKeyLength(
                f_key_type,
                f_mat_serialized.len(),
            ));
        }
        if s_key_type != f_key_type {
            return Err(SignalProtocolError::MismatchSKEMSecretKeyMaterial(
                s_key_type, f_key_type,
            ));
        }
        let s_mat = Key::<Secret>::deserialize(s_mat_serialized)?;
        let f_mat = Key::<FSecret>::deserialize(f_mat_serialized)?;
        if s_mat.key_type != f_mat.key_type {
            return Err(SignalProtocolError::MismatchSKEMSecretKeyMaterial(
                s_mat.key_type,
                f_mat.key_type,
            ));
        }
        Ok(SecretKeyMaterial {
            key_type: s_key_type,
            s_mat: s_mat,
            f_mat: f_mat,
        })
    }
}

impl TryFrom<&[u8]> for Key<Public> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl TryFrom<&[u8]> for Key<Secret> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl TryFrom<&[u8]> for Key<FSecret> {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
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

impl subtle::ConstantTimeEq for KeyType {
    /// A constant-time comparison if two `KeyType` instances are equal.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(&other.value())
    }
}

impl PartialEq for KeyType {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl subtle::ConstantTimeEq for PublicKeyMaterial {
    /// A constant-time comparison if two `PublicKeyMaterial` instances are equal.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.b_mat.ct_eq(&other.b_mat) & self.key_type.ct_eq(&other.key_type)
    }
}

impl PartialEq for PublicKeyMaterial {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for PublicKeyMaterial {}

pub type PublicKey = Key<Public>;
pub type SecretKey = Key<Secret>;
pub type FSecretKey = Key<FSecret>;

#[derive(Clone)]
pub struct KeyPair<T: Role> {
    pub role: PhantomData<T>,
    pub public_key_mat: PublicKeyMaterial,
    pub secret_key_mat: SecretKeyMaterial,
}

pub trait Role {
    fn value() -> u8;
    fn new_key_pair(
        public_key_material: PublicKeyMaterial,
        secret_key_material: SecretKeyMaterial,
    ) -> KeyPair<Self>
    where
        Self: Sized;
    fn generate_key_pair(key_type: KeyType, pp: &PublicParameters) -> KeyPair<Self>
    where
        Self: Sized;

    fn generate_key_pair_from_seed(key_type: KeyType, seed: &[u8]) -> KeyPair<Self>
    where
        Self: Sized,
    {
        let pp = PublicParameters::from_seed(seed.into());
        Self::generate_key_pair(key_type, &pp)
    }

    fn from_public_and_private(
        public_key_mat_serialized: &[u8],
        secret_key_mat_serialized: &[u8],
    ) -> Result<KeyPair<Self>>
    where
        Self: Sized;
}

#[derive(Clone, Debug)]
pub struct Encapsulator;
impl Encapsulator {
    pub fn generate_key_pair(key_type: KeyType, pp: &PublicParameters) -> EncapsulatorKeyPair {
        Role::generate_key_pair(key_type, pp)
    }

    pub fn generate_key_pair_from_seed(key_type: KeyType, seed: &[u8]) -> EncapsulatorKeyPair {
        Role::generate_key_pair_from_seed(key_type, seed)
    }

    pub fn from_public_and_private(
        public_key_mat_serialized: &[u8],
        secret_key_mat_serialized: &[u8],
    ) -> Result<EncapsulatorKeyPair> {
        Role::from_public_and_private(public_key_mat_serialized, secret_key_mat_serialized)
    }
}

pub type EncapsulatorKeyPair = KeyPair<Encapsulator>;

impl Role for Encapsulator {
    fn value() -> u8 {
        0x1
    }

    fn new_key_pair(
        public_key_material: PublicKeyMaterial,
        secret_key_material: SecretKeyMaterial,
    ) -> EncapsulatorKeyPair {
        assert_eq!(public_key_material.key_type, secret_key_material.key_type);
        EncapsulatorKeyPair {
            role: PhantomData,
            public_key_mat: public_key_material,
            secret_key_mat: secret_key_material,
        }
    }

    fn generate_key_pair(key_type: KeyType, pp: &PublicParameters) -> EncapsulatorKeyPair {
        let (pub_key_mat, sec_key_mat) = key_type.parameters().generate_encapsulator(pp);
        EncapsulatorKeyPair {
            role: PhantomData,
            public_key_mat: pub_key_mat,
            secret_key_mat: sec_key_mat,
        }
    }

    /// Deserialize public and secret key material that were serialized by `PublicKeyMaterial::serialize()`
    /// and `SecretKeyMaterial::serialize()` respectively.
    fn from_public_and_private(
        public_key_mat_serialized: &[u8],
        secret_key_mat_serialized: &[u8],
    ) -> Result<EncapsulatorKeyPair> {
        let public_key_mat = PublicKeyMaterial::deserialize(public_key_mat_serialized)?;
        let secret_key_mat = SecretKeyMaterial::deserialize(secret_key_mat_serialized)?;

        if public_key_mat.key_type != secret_key_mat.key_type {
            Err(SignalProtocolError::WrongSKEMKeyType(
                public_key_mat.key_type.value(),
                secret_key_mat.key_type.value(),
            ))
        } else {
            Ok(EncapsulatorKeyPair {
                role: PhantomData,
                public_key_mat,
                secret_key_mat,
            })
        }
    }
}
#[derive(Clone)]
pub struct Decapsulator;
impl Decapsulator {
    pub fn generate_key_pair(key_type: KeyType, pp: &PublicParameters) -> DecapsulatorKeyPair {
        Role::generate_key_pair(key_type, pp)
    }

    pub fn generate_key_pair_from_seed(key_type: KeyType, seed: &[u8]) -> EncapsulatorKeyPair {
        Role::generate_key_pair_from_seed(key_type, seed)
    }

    pub fn from_public_and_private(
        public_key_mat_serialized: &[u8],
        secret_key_mat_serialized: &[u8],
    ) -> Result<DecapsulatorKeyPair> {
        Role::from_public_and_private(public_key_mat_serialized, secret_key_mat_serialized)
    }
}

pub type DecapsulatorKeyPair = KeyPair<Decapsulator>;

impl Role for Decapsulator {
    fn value() -> u8 {
        0x2
    }

    fn new_key_pair(
        public_key_material: PublicKeyMaterial,
        secret_key_material: SecretKeyMaterial,
    ) -> DecapsulatorKeyPair {
        assert_eq!(public_key_material.key_type, secret_key_material.key_type);
        DecapsulatorKeyPair {
            role: PhantomData,
            public_key_mat: public_key_material,
            secret_key_mat: secret_key_material,
        }
    }

    fn generate_key_pair(key_type: KeyType, pp: &PublicParameters) -> DecapsulatorKeyPair {
        let (pub_key_mat, sec_key_mat) = key_type.parameters().generate_decapsulator(pp);
        DecapsulatorKeyPair {
            role: PhantomData,
            public_key_mat: pub_key_mat,
            secret_key_mat: sec_key_mat,
        }
    }

    /// Deserialize public and secret key material that were serialized by `PublicKeyMaterial::serialize()`
    /// and `SecretKeyMaterial::serialize()` respectively.
    fn from_public_and_private(
        public_key_mat_serialized: &[u8],
        secret_key_mat_serialized: &[u8],
    ) -> Result<DecapsulatorKeyPair> {
        let public_key_mat = PublicKeyMaterial::deserialize(public_key_mat_serialized)?;
        let secret_key_mat = SecretKeyMaterial::deserialize(secret_key_mat_serialized)?;

        if public_key_mat.key_type != secret_key_mat.key_type {
            Err(SignalProtocolError::WrongSKEMKeyType(
                public_key_mat.key_type.value(),
                secret_key_mat.key_type.value(),
            ))
        } else {
            Ok(DecapsulatorKeyPair {
                role: PhantomData,
                public_key_mat,
                secret_key_mat,
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
        let key_type = KeyType::try_from(value[0])?;
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

    /// Create a binary representation of the ciphertext that includes a protocol identifier.
    pub fn serialize(&self) -> SerializedCiphertext {
        let mut result = Vec::with_capacity(1 + self.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(self.data);
        result.into_boxed_slice()
    }
}

/// Utility type to handle serialization and deserialization of tag data
struct Tag<'a> {
    key_type: KeyType,
    data: &'a [u8],
}

impl<'a> Tag<'a> {
    /// Create a `Tag` instance from a byte string created with the
    /// function `Tag::serialize(&self)`.
    pub fn deserialize(value: &'a [u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        if value.len() != key_type.parameters().tag_length() + 1 {
            return Err(SignalProtocolError::BadSKEMTagLength(key_type, value.len()));
        }
        Ok(Tag {
            key_type,
            data: &value[1..],
        })
    }

    /// Create a binary representation of the tag that includes a protocol identifier.
    pub fn serialize(&self) -> SerializedTag {
        let mut result = Vec::with_capacity(1 + self.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(self.data);
        result.into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_public_key() {
        let key_type = KeyType::Frodokexp;
        let pp = key_type.parameters().generate_public_parameters(true);
        let (enc_pk, _) = key_type.parameters().generate_encapsulator(&pp);
        let enc_pk_serialized = enc_pk.serialize();
        let enc_pk_deserialized = PublicKeyMaterial::deserialize(&enc_pk_serialized).unwrap();
        assert_eq!(enc_pk.key_type, enc_pk_deserialized.key_type);
        assert_eq!(enc_pk.b_mat, enc_pk_deserialized.b_mat);
    }

    #[test]
    fn test_correctness() {
        for _ in 0..10 {
            for key_type in [KeyType::Frodokexp] {
                for store_matrix in [true, false] {
                    let pp = key_type
                        .parameters()
                        .generate_public_parameters(store_matrix);
                    let (enc_pk, enc_sk) = key_type.parameters().generate_encapsulator(&pp);
                    let (dec_pk, dec_sk) = key_type.parameters().generate_decapsulator(&pp);
                    let (ss, ct, tag) = dec_pk.encapsulate(&enc_pk, &enc_sk);
                    let ss_dec = dec_sk.decapsulate(&dec_pk, &enc_pk, &ct, &tag).unwrap();
                    assert_eq!(ss, ss_dec);
                }
            }
        }
    }
}
