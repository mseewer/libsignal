//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::{skem, PrivateKey, Result, SignalProtocolError};
use prost::Message;
use std::fmt;

/// A unique identifier selecting among this client's known signed pre-keys.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct FrodokexpPreKeyId(u32);

impl From<u32> for FrodokexpPreKeyId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<FrodokexpPreKeyId> for u32 {
    fn from(value: FrodokexpPreKeyId) -> Self {
        value.0
    }
}

impl fmt::Display for FrodokexpPreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct FrodokexpPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
    seed: skem::Seed,
}

impl FrodokexpPreKeyRecord {
    pub fn new(
        id: FrodokexpPreKeyId,
        timestamp: u64,
        key_pair: &skem::DecapsulatorKeyPair,
        signature: &[u8],
        seed: &skem::Seed,
    ) -> Self {
        let public_key = key_pair.public_key_mat.serialize().into_vec();
        let private_key = key_pair.secret_key_mat.serialize().into_vec();
        let signature = signature.to_vec();
        Self {
            signed_pre_key: SignedPreKeyRecordStructure {
                id: id.into(),
                timestamp,
                public_key,
                private_key,
                signature,
            },
            seed: seed.clone(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let key_vec = self.signed_pre_key.encode_to_vec();
        let seed_vec = self.seed.to_vec();
        let combined_vec = [seed_vec, key_vec].concat();
        Ok(combined_vec)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let seed_length = skem::KeyType::Frodokexp.get_seed_length();
        let seed_data = data[..seed_length].to_vec();
        let key_data = data[seed_length..].to_vec();
        let seed = seed_data.into_boxed_slice();
        let pre_key = SignedPreKeyRecordStructure::decode(key_data.as_ref())
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(Self {
            signed_pre_key: pre_key,
            seed,
        })
    }

    pub fn id(&self) -> Result<FrodokexpPreKeyId> {
        Ok(self.signed_pre_key.id.into())
    }

    pub fn timestamp(&self) -> Result<u64> {
        Ok(self.signed_pre_key.timestamp)
    }

    pub fn signature(&self) -> Result<Vec<u8>> {
        Ok(self.signed_pre_key.signature.clone())
    }

    pub fn public_key(&self) -> Result<skem::PublicKeyMaterial> {
        let public_key_serialized = self.signed_pre_key.public_key.as_ref();
        skem::PublicKeyMaterial::deserialize(public_key_serialized)
    }

    pub fn key_pair(&self) -> Result<skem::DecapsulatorKeyPair> {
        skem::Decapsulator::from_public_and_private(
            &self.signed_pre_key.public_key,
            &self.signed_pre_key.private_key,
        )
    }

    pub fn seed(&self) -> Result<skem::Seed> {
        Ok(self.seed.clone())
    }
}

impl FrodokexpPreKeyRecord {
    pub fn secret_key(&self) -> Result<skem::SecretKeyMaterial> {
        skem::SecretKeyMaterial::deserialize(&self.signed_pre_key.private_key)
    }
}

impl FrodokexpPreKeyRecord {
    pub fn generate(
        frodokexp_key_type: skem::KeyType,
        frodokexp_public_parameters: &skem::PublicParameters,
        id: FrodokexpPreKeyId,
        signing_key: &PrivateKey,
    ) -> Result<FrodokexpPreKeyRecord> {
        let seed = frodokexp_public_parameters.get_seed().clone();
        let key_pair =
            skem::Decapsulator::generate_key_pair(frodokexp_key_type, frodokexp_public_parameters);
        let mut rng = rand::rngs::OsRng;
        let signature = signing_key
            .calculate_signature(&key_pair.public_key_mat.serialize(), &mut rng)?
            .into_vec();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Time should move forward")
            .as_millis();
        let record = FrodokexpPreKeyRecord::new(
            id,
            timestamp.try_into().expect("Timestamp too large"),
            &key_pair,
            &signature,
            &seed,
        );
        Ok(record)
    }
}
