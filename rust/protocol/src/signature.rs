use crate::{Result, SignalProtocolError};
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

pub struct Signature {
    pub version: SignatureVersion,
    pub data: SignatureData,
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let version = SignatureVersion::from_u8(bytes[0])?;
        let signature = match version {
            SignatureVersion::Legacy => {
                SignatureData::Legacy(bytes[1..].to_vec().into_boxed_slice())
            }
            SignatureVersion::Falcon => {
                SignatureData::Falcon(FalconSignature::from_bytes(&bytes[1..])?)
            }
        };
        Ok(Self {
            version,
            data: signature,
        })
    }

    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = vec![self.version.to_u8()];
        match &self.data {
            SignatureData::Legacy(sig) => bytes.extend_from_slice(sig),
            SignatureData::Falcon(sig) => bytes.extend_from_slice(sig.as_bytes()),
        }
        bytes.into_boxed_slice()
    }

    pub fn new_from_falcon_signature(signature: FalconSignature) -> Self {
        Self {
            version: SignatureVersion::Falcon,
            data: SignatureData::Falcon(signature),
        }
    }

    pub fn new_from_legacy_signature(signature: Box<[u8]>) -> Self {
        Self {
            version: SignatureVersion::Legacy,
            data: SignatureData::Legacy(signature),
        }
    }

    pub fn get_raw_falcon_signature(&self) -> Option<&FalconSignature> {
        match &self.data {
            SignatureData::Falcon(sig) => Some(sig),
            _ => None,
        }
    }

    pub fn get_raw_legacy_signature(&self) -> Option<&Box<[u8]>> {
        match &self.data {
            SignatureData::Legacy(sig) => Some(sig),
            _ => None,
        }
    }
}

pub enum SignatureData {
    Legacy(Box<[u8]>), // see curve/curve25519.rs -> 64 bytes
    Falcon(FalconSignature),
}

#[derive(PartialEq)]
pub enum SignatureVersion {
    Legacy,
    Falcon,
}

impl SignatureVersion {
    pub fn from_u8(version: u8) -> Result<Self> {
        match version {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::Falcon),
            x => Err(SignalProtocolError::InvalidSignatureVersion(x)),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Legacy => 0,
            Self::Falcon => 1,
        }
    }
}

#[derive(Clone)]
pub struct FalconSignature(falcon1024::SignedMessage);
// pub type FalconPublicKey = falcon1024::PublicKey;

#[derive(Clone, PartialEq)]
pub struct FalconSecretKey(falcon1024::SecretKey);

impl FalconSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = falcon1024::SecretKey::from_bytes(bytes)
            .map_err(|_| SignalProtocolError::FalconReadingFromBytesError)?;
        Ok(Self(secret_key))
    }

    pub fn from_secret_key(secret_key: falcon1024::SecretKey) -> Self {
        Self(secret_key)
    }
}

#[derive(Clone, PartialEq)]
pub struct FalconPublicKey(falcon1024::PublicKey);

impl FalconPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = falcon1024::PublicKey::from_bytes(bytes)
            .map_err(|_| SignalProtocolError::FalconReadingFromBytesError)?;
        Ok(Self(public_key))
    }

    pub fn from_public_key(public_key: falcon1024::PublicKey) -> Self {
        Self(public_key)
    }
}

impl FalconSignature {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signed_messge = falcon1024::SignedMessage::from_bytes(bytes)
            .map_err(|_| SignalProtocolError::FalconReadingFromBytesError)?;
        Ok(Self(signed_messge))
    }

    pub fn sign_with_falcon(secret_key: &FalconSecretKey, msg: &[u8]) -> Self {
        Self {
            0: falcon1024::sign(msg, &secret_key.0),
        }
    }

    pub fn verify_signature(
        pk: &FalconPublicKey,
        msg: &[u8],
        signature: &FalconSignature,
    ) -> Result<()> {
        // falcon1024::verify(msg, signature, pk)
        let signed_msg = &signature.0;
        let verified_msg = falcon1024::open(signed_msg, &pk.0);
        if verified_msg.is_err() {
            return Err(SignalProtocolError::FalconSignatureVerificationError);
        }
        if verified_msg.unwrap() == msg {
            Ok(())
        } else {
            Err(SignalProtocolError::FalconSignatureVerificationError)
        }
    }
}

#[derive(Clone)]
pub struct FalconKeyPair {
    pub public_key: FalconPublicKey,
    pub secret_key: FalconSecretKey,
}

impl FalconKeyPair {
    pub fn generate_falcon_key_pair() -> Self {
        let (pk, sk) = falcon1024::keypair();
        Self {
            public_key: FalconPublicKey(pk),
            secret_key: FalconSecretKey(sk),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.public_key.as_bytes());
        bytes.extend_from_slice(&self.secret_key.as_bytes());
        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let public_key = FalconPublicKey::from_bytes(&bytes[..1024 / 8])
            .map_err(|_| SignalProtocolError::FalconReadingFromBytesError)?;
        let secret_key = FalconSecretKey::from_bytes(&bytes[1024 / 8..])
            .map_err(|_| SignalProtocolError::FalconReadingFromBytesError)?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
}
