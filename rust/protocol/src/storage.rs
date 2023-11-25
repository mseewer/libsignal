//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Interfaces in [traits] and reference implementations in [inmem] for various mutable stores.

#![warn(missing_docs)]

mod inmem;
mod traits;

pub use inmem::{
    InMemFalconSignatureStore, InMemFrodokexpPreKeyStore, InMemIdentityKeyStore,
    InMemKyberLongTermKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore, InMemSenderKeyStore,
    InMemSessionStore, InMemSignalProtocolStore, InMemSignedPreKeyStore,
};
pub use traits::{
    Direction, FalconSignatureStore, FrodokexpPreKeyStore, IdentityKeyStore, KyberLongTermKeyStore,
    KyberPreKeyStore, PreKeyStore, ProtocolStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};
