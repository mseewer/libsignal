//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Traits defining several stores used throughout the Signal Protocol.

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::Result;
use crate::long_term_keys::{KyberLongTermKeyPair, KyberLongTermKeyPublic};
use crate::sender_keys::SenderKeyRecord;
use crate::signature::{FalconKeyPair, FalconPublicKey, FalconSignature};
use crate::state::{
    FrodokexpPreKeyId, FrodokexpPreKeyRecord, KyberPreKeyId, KyberPreKeyRecord, PreKeyId,
    PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord,
};
use crate::{IdentityKey, IdentityKeyPair, ProtocolAddress};

// TODO: consider moving this enum into utils.rs?
/// Each Signal message can be considered to have exactly two participants, a sender and receiver.
///
/// [IdentityKeyStore::is_trusted_identity] uses this to ensure the identity provided is configured
/// for the appropriate role.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    /// We are in the context of sending a message.
    Sending,
    /// We are in the context of receiving a message.
    Receiving,
}

/// Interface defining the identity store, which may be in-memory, on-disk, etc.
///
/// Signal clients usually use the identity store in a [TOFU] manner, but this is not required.
///
/// [TOFU]: https://en.wikipedia.org/wiki/Trust_on_first_use
#[async_trait(?Send)]
pub trait IdentityKeyStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair>;

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(&self) -> Result<u32>;

    // TODO: make this into an enum instead of a bool!
    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value should be `Ok(false)`.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool>;

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool>;

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>>;
}

/// Interface defining the long-term Kyber key store
#[async_trait(?Send)]
pub trait KyberLongTermKeyStore {
    /// Return the single specific long-term Kyber key the store is assumed to represent, with private key.
    async fn get_local_kyber_long_term_key_pair(&self) -> Result<KyberLongTermKeyPair>;

    /// Record a Kyber long-term key into the store.
    async fn save_kyber_longterm(
        &mut self,
        address: &ProtocolAddress,
        kyber_long_term_key_public: &KyberLongTermKeyPublic,
    ) -> Result<bool>;

    /// Return the public Kyber long-term key for the given `address`, if known.
    async fn get_kyber_long_term_key(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<KyberLongTermKeyPublic>>;
}

/// Interface defining the long-term Falcon signature key store
#[async_trait(?Send)]
pub trait FalconSignatureStore {
    /// Return the single specific long-term Falcon signature key, with private key.
    async fn get_falcon_key_pair(&self) -> Result<FalconKeyPair>;

    /// Save someone else's Falcon public key.
    async fn save_falcon_public(
        &mut self,
        address: &ProtocolAddress,
        falcon_public_key: &FalconPublicKey,
    ) -> Result<bool>;

    /// Sign a message with the Falcon signature key.
    async fn sign_with_falcon(&self, msg: &[u8]) -> FalconSignature;

    /// Verify a signature with the Falcon signature key, if it corresponds to the given message, signing key is based on the address.
    async fn verify_signature(
        &self,
        address: &ProtocolAddress,
        msg: &[u8],
        signature: &FalconSignature,
    ) -> Result<()>;

    /// Verify a signature with the given Falcon public key, if it corresponds to the given message
    /// public_key is the signing key.
    async fn verify_signature_with_public_key(
        &self,
        public_key: &FalconPublicKey,
        msg: &[u8],
        signature: &FalconSignature,
    ) -> Result<()>;

    /// Return the public Falcon signature key for the given `address`, if known.
    async fn get_falcon_public(&self, address: &ProtocolAddress)
        -> Result<Option<FalconPublicKey>>;
}
/// Interface for storing pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait PreKeyStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord>;

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()>;

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()>;
}

/// Interface for storing signed pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait SignedPreKeyStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord>;

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()>;
}

/// Interface for storing signed Kyber pre-keys downloaded from a server.
///
/// NB: libsignal makes no distinction between one-time and last-resort pre-keys.
#[async_trait(?Send)]
pub trait KyberPreKeyStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> Result<KyberPreKeyRecord>;

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()>;

    /// Mark the entry for `kyber_prekey_id` as "used".
    /// This would mean different things for one-time and last-resort Kyber keys.
    async fn mark_kyber_pre_key_used(&mut self, kyber_prekey_id: KyberPreKeyId) -> Result<()>;
}

/// Interface for storing signed Frodokexp decaps pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait FrodokexpPreKeyStore {
    /// Look up the signed frodokexp pre-key corresponding to `frodokexp_prekey_id`.
    async fn get_frodokexp_pre_key(
        &self,
        frodokexp_prekey_id: FrodokexpPreKeyId,
    ) -> Result<FrodokexpPreKeyRecord>;

    /// Set the entry for `frodokexp_prekey_id` to the value of `record`.
    async fn save_frodokexp_pre_key(
        &mut self,
        frodokexp_prekey_id: FrodokexpPreKeyId,
        record: &FrodokexpPreKeyRecord,
    ) -> Result<()>;

    /// Mark the entry for `frodokexp_prekey_id` as "used".
    /// This would mean different things for one-time and last-resort Frodokexp keys.
    async fn mark_frodokexp_pre_key_used(
        &mut self,
        frodokexp_prekey_id: FrodokexpPreKeyId,
    ) -> Result<()>;
}

/// Interface for a Signal client instance to store a session associated with another particular
/// separate Signal client instance.
///
/// This [SessionRecord] object between a pair of Signal clients is used to drive the state for the
/// forward-secret message chain in the [Double Ratchet] protocol.
///
/// [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
#[async_trait(?Send)]
pub trait SessionStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>>;

    /// Set the entry for `address` to the value of `record`.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()>;
}

/// Interface for storing sender key records, allowing multiple keys per user.
#[async_trait(?Send)]
pub trait SenderKeyStore {
    /// Assign `record` to the entry for `(sender, distribution_id)`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        // TODO: pass this by value!
        record: &SenderKeyRecord,
    ) -> Result<()>;

    /// Look up the entry corresponding to `(sender, distribution_id)`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>>;
}

/// Mixes in all the store interfaces defined in this module.
pub trait ProtocolStore:
    SessionStore
    + PreKeyStore
    + SignedPreKeyStore
    + KyberPreKeyStore
    + FrodokexpPreKeyStore
    + IdentityKeyStore
    + KyberLongTermKeyStore
    + FalconSignatureStore
{
}
