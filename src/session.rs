//! Session X3DH + Double Ratchet : chiffrement/déchiffrement Signal.

use crate::stores::InMemoryStores;
use crate::stores_wrappers::{
    IdentityStoreView, KyberPreKeyStoreView, PreKeyStoreView, SessionStoreView,
    SignedPreKeyStoreView,
};
use libsignal_protocol::*;
use rand::{CryptoRng, Rng};

pub async fn establish_session<R: Rng + CryptoRng>(
    store: &mut InMemoryStores,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    bundle: &PreKeyBundle,
    rng: &mut R,
) -> std::result::Result<(), SignalProtocolError> {
    let mut identity_store = IdentityStoreView {
        identity_key_pair: store.identity_key_pair.clone(),
        registration_id: store.registration_id,
        identities: &store.identities,
    };
    let mut session_store = SessionStoreView {
        sessions: &store.sessions,
    };

    process_prekey_bundle(
        remote_address,
        local_address,
        &mut session_store,
        &mut identity_store,
        bundle,
        std::time::SystemTime::now(),
        rng,
    )
    .await
}

pub async fn encrypt_message<R: Rng + CryptoRng>(
    store: &mut InMemoryStores,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    plaintext: &[u8],
    rng: &mut R,
) -> std::result::Result<CiphertextMessage, SignalProtocolError> {
    let mut identity_store = IdentityStoreView {
        identity_key_pair: store.identity_key_pair.clone(),
        registration_id: store.registration_id,
        identities: &store.identities,
    };
    let mut session_store = SessionStoreView {
        sessions: &store.sessions,
    };

    message_encrypt(
        plaintext,
        remote_address,
        local_address,
        &mut session_store,
        &mut identity_store,
        std::time::SystemTime::now(),
        rng,
    )
    .await
}

pub async fn decrypt_prekey_message<R: Rng + CryptoRng>(
    store: &mut InMemoryStores,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    ciphertext: &PreKeySignalMessage,
    rng: &mut R,
) -> std::result::Result<Vec<u8>, SignalProtocolError> {
    let mut identity_store = IdentityStoreView {
        identity_key_pair: store.identity_key_pair.clone(),
        registration_id: store.registration_id,
        identities: &store.identities,
    };
    let mut session_store = SessionStoreView {
        sessions: &store.sessions,
    };
    let mut pre_key_store = PreKeyStoreView {
        pre_keys: &store.pre_keys,
    };
    let signed_pre_key_store = SignedPreKeyStoreView {
        signed_pre_keys: &store.signed_pre_keys,
    };
    let mut kyber_pre_key_store = KyberPreKeyStoreView {
        kyber_pre_keys: &store.kyber_pre_keys,
    };

    message_decrypt_prekey(
        ciphertext,
        remote_address,
        local_address,
        &mut session_store,
        &mut identity_store,
        &mut pre_key_store,
        &signed_pre_key_store,
        &mut kyber_pre_key_store,
        rng,
    )
    .await
}

pub async fn decrypt_message<R: Rng + CryptoRng>(
    store: &mut InMemoryStores,
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    ciphertext: &SignalMessage,
    rng: &mut R,
) -> std::result::Result<Vec<u8>, SignalProtocolError> {
    let mut identity_store = IdentityStoreView {
        identity_key_pair: store.identity_key_pair.clone(),
        registration_id: store.registration_id,
        identities: &store.identities,
    };
    let mut session_store = SessionStoreView {
        sessions: &store.sessions,
    };

    message_decrypt_signal(
        ciphertext,
        remote_address,
        local_address,
        &mut session_store,
        &mut identity_store,
        rng,
    )
    .await
}
