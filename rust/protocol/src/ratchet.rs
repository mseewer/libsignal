//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

pub(crate) use self::keys::{ChainKey, MessageKeys, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::protocol::{
    CIPHERTEXT_MESSAGE_CURRENT_VERSION, CIPHERTEXT_MESSAGE_PRE_FRODOKEXP_KYBER_VERSION,
    CIPHERTEXT_MESSAGE_PRE_FRODOKEXP_VERSION,
};
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord};
use rand::{CryptoRng, Rng};

fn derive_keys(has_kyber: bool, has_frodokexp: bool, secret_input: &[u8]) -> (RootKey, ChainKey) {
    let label = if has_kyber && has_frodokexp {
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024_FRODOKEXP".as_slice()
    } else if has_kyber {
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024".as_slice()
    } else if has_frodokexp {
        b"WhisperText_X25519_SHA-256_FRODOKEXP".as_slice()
    } else {
        b"WhisperText".as_slice()
    };
    derive_keys_with_label(label, secret_input)
}

fn message_version(has_kyber: bool, has_frodokexp: bool) -> u8 {
    if has_kyber && has_frodokexp {
        CIPHERTEXT_MESSAGE_CURRENT_VERSION
    } else if has_kyber {
        CIPHERTEXT_MESSAGE_PRE_FRODOKEXP_VERSION
    } else {
        CIPHERTEXT_MESSAGE_PRE_FRODOKEXP_KYBER_VERSION
    }
}

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey) {
    let mut secrets = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes) = secrets.split_at(32);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);

    (root_key, chain_key)
}

pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    let kyber_ciphertext = parameters.their_kyber_pre_key().map(|kyber_public| {
        let (ss, ct) = kyber_public.encapsulate();
        secrets.extend_from_slice(ss.as_ref());
        ct
    });
    let has_kyber = parameters.their_kyber_pre_key().is_some();

    let frodokexp_ciphertext_tag_pk = parameters.their_frodokexp_pre_key().map(|their_public| {
        let (own_public, own_secret) = parameters
            .own_frodokexp_key_pair()
            .map(|frodokexp_key_pair| {
                (
                    frodokexp_key_pair.public_key_mat.to_owned(),
                    frodokexp_key_pair.secret_key_mat.to_owned(),
                )
            })
            .expect("Own key pair must be set");
        let (ss, ct, tag) = their_public.encapsulate(&own_public, &own_secret);
        secrets.extend_from_slice(ss.as_ref());
        (ct, tag, own_public)
    });
    let has_frodokexp = parameters.their_frodokexp_pre_key().is_some();

    let kyber_longterm_ciphertext = parameters.their_kyber_long_term_key().map(|kyber_public| {
        let (ss, ct) = kyber_public.encapsulate();
        secrets.extend_from_slice(ss.as_ref());
        ct
    });

    let has_kwaay = has_frodokexp && parameters.their_kyber_long_term_key().is_some();

    let (root_key, chain_key) = derive_keys(has_kyber, has_kwaay, &secrets);

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let mut session = SessionState::new(
        message_version(has_kyber, has_kwaay),
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    if let Some(kyber_ciphertext) = kyber_ciphertext {
        session.set_kyber_ciphertext(kyber_ciphertext);
    }
    if let Some((frodokexp_ciphertext, frodokexp_tag, frodokexp_own_public_key)) =
        frodokexp_ciphertext_tag_pk
    {
        session.set_frodokexp_payload(
            frodokexp_ciphertext,
            frodokexp_tag,
            frodokexp_own_public_key,
        );
    }
    if let Some(kyber_longterm_ciphertext) = kyber_longterm_ciphertext {
        session.set_kyber_longterm_ciphertext(kyber_longterm_ciphertext);
    }

    Ok(session)
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
    }

    match (
        parameters.our_kyber_pre_key_pair(),
        parameters.their_kyber_ciphertext(),
    ) {
        (Some(key_pair), Some(ciphertext)) => {
            let ss = key_pair.secret_key.decapsulate(ciphertext)?;
            secrets.extend_from_slice(ss.as_ref());
        }
        (None, None) => (), // Alice does not support kyber prekeys
        _ => {
            panic!("Either both or none of the kyber key pair and ciphertext can be provided")
        }
    }
    let has_kyber = parameters.our_kyber_pre_key_pair().is_some();

    match (
        parameters.our_frodokexp_pre_key_pair(),
        parameters.their_frodokexp_ciphertext(),
        parameters.their_frodokexp_tag(),
        parameters.their_frodokexp_public_key(),
    ) {
        (Some(our_key_pair), Some(ciphertext), Some(tag), Some(their_public_key)) => {
            let ss = our_key_pair.secret_key_mat.decapsulate(
                &our_key_pair.public_key_mat,
                their_public_key,
                ciphertext,
                tag,
            )?;
            secrets.extend_from_slice(ss.as_ref());
        }
        (None, None, None, None) => (), // Alice does not support frodokexp prekeys
        _ => {
            panic!(
                "Either all or none of the frodokexp key pair, ciphertext and tag can be provided"
            )
        }
    }
    let has_frodokexp = parameters.our_frodokexp_pre_key_pair().is_some();

    match (
        parameters.our_kyber_long_term_key_pair(),
        parameters.their_kyber_longterm_ciphertext(),
    ) {
        (Some(key_pair), Some(ciphertext)) => {
            let ss = key_pair.secret_key.decapsulate(ciphertext)?;
            secrets.extend_from_slice(ss.as_ref());
        }
        (_, None) => (), // Alice does not support kyber longterm keys
        _ => {
            panic!("Either both or none of the kyber longterm keys and ciphertext can be provided")
        }
    }

    let has_kwaay = has_frodokexp && parameters.our_kyber_long_term_key_pair().is_some();

    let (root_key, chain_key) = derive_keys(has_kyber, has_kwaay, &secrets);

    let session = SessionState::new(
        message_version(has_kyber, has_kwaay),
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
