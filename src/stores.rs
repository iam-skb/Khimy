//! Conteneur InMemoryStores : garde tous les HashMaps en RAM.
//!
//! Les implémentations des traits libsignal sont dans `stores_wrappers.rs`.
//! Ici on fournit juste le conteneur et une méthode pour obtenir les 5 vues.

use libsignal_protocol::*;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::stores_wrappers::{
    IdentityStoreView, KyberPreKeyStoreView, PreKeyStoreView, SessionStoreView,
    SignedPreKeyStoreView,
};

/// Conteneur en mémoire pour tous les stores de Signal.
pub struct InMemoryStores {
    pub identity_key_pair: IdentityKeyPair,
    pub registration_id: u32,
    pub identities: Mutex<HashMap<String, IdentityKey>>,
    pub pre_keys: Mutex<HashMap<PreKeyId, PreKeyRecord>>,
    pub signed_pre_keys: Mutex<HashMap<SignedPreKeyId, SignedPreKeyRecord>>,
    pub kyber_pre_keys: Mutex<HashMap<KyberPreKeyId, KyberPreKeyRecord>>,
    pub sessions: Mutex<HashMap<String, SessionRecord>>,
}

impl InMemoryStores {
    pub fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity_key_pair,
            registration_id,
            identities: Mutex::new(HashMap::new()),
            pre_keys: Mutex::new(HashMap::new()),
            signed_pre_keys: Mutex::new(HashMap::new()),
            kyber_pre_keys: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}
