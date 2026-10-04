//! In-memory stores pour libsignal-protocol.
//!
//! Ces stores gardent en RAM les clés et sessions de Khimy.
//! Ils implémentent les 5 traits requis par libsignal :
//! - IdentityKeyStore
//! - PreKeyStore
//! - SignedPreKeyStore
//! - KyberPreKeyStore
//! - SessionStore

use async_trait::async_trait;
use libsignal_protocol::*;
use std::collections::HashMap;
use std::sync::Mutex;

/// Alias pratique pour le Result de libsignal (l'erreur est SignalProtocolError).
type Result<T> = std::result::Result<T, SignalProtocolError>;

/// Conteneur en mémoire pour tous les stores de Signal.
pub struct InMemoryStores {
    /// Notre paire de clés d'identité (privée + publique).
    pub identity_key_pair: IdentityKeyPair,
    /// Notre registration id local.
    pub registration_id: u32,
    /// Identités connues des contacts, indexées par leur adresse.
    pub identities: Mutex<HashMap<String, IdentityKey>>,
    /// Pre-keys à usage unique.
    pub pre_keys: Mutex<HashMap<PreKeyId, PreKeyRecord>>,
    /// Signed pre-keys.
    pub signed_pre_keys: Mutex<HashMap<SignedPreKeyId, SignedPreKeyRecord>>,
    /// Kyber pre-keys (post-quantique).
    pub kyber_pre_keys: Mutex<HashMap<KyberPreKeyId, KyberPreKeyRecord>>,
    /// Sessions actives, indexées par adresse du contact.
    pub sessions: Mutex<HashMap<String, SessionRecord>>,
}

impl InMemoryStores {
    /// Crée un nouveau store avec la paire de clés et le registration id donnés.
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

    /// Clé String utilisée pour indexer une adresse dans les HashMaps.
    fn addr_key(address: &ProtocolAddress) -> String {
        format!("{}.{}", address.name(), u32::from(address.device_id()))
    }
}

// ============================================================
// IdentityKeyStore
// ============================================================

#[async_trait(?Send)]
impl IdentityKeyStore for InMemoryStores {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.identity_key_pair.clone())
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange> {
        let key = Self::addr_key(address);
        let mut ids = self.identities.lock().unwrap();
        let changed = ids.insert(key, *identity).is_some();
        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool> {
        let key = Self::addr_key(address);
        let ids = self.identities.lock().unwrap();
        Ok(ids.get(&key).map(|known| known == identity).unwrap_or(true))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>> {
        let key = Self::addr_key(address);
        let ids = self.identities.lock().unwrap();
        Ok(ids.get(&key).copied())
    }
}

// ============================================================
// PreKeyStore
// ============================================================

#[async_trait(?Send)]
impl PreKeyStore for InMemoryStores {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        let keys = self.pre_keys.lock().unwrap();
        keys.get(&prekey_id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<()> {
        let mut keys = self.pre_keys.lock().unwrap();
        keys.insert(prekey_id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        let mut keys = self.pre_keys.lock().unwrap();
        keys.remove(&prekey_id);
        Ok(())
    }
}

// ============================================================
// SignedPreKeyStore
// ============================================================

#[async_trait(?Send)]
impl SignedPreKeyStore for InMemoryStores {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord> {
        let keys = self.signed_pre_keys.lock().unwrap();
        keys.get(&signed_prekey_id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        let mut keys = self.signed_pre_keys.lock().unwrap();
        keys.insert(signed_prekey_id, record.clone());
        Ok(())
    }
}

// ============================================================
// KyberPreKeyStore
// ============================================================

#[async_trait(?Send)]
impl KyberPreKeyStore for InMemoryStores {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord> {
        let keys = self.kyber_pre_keys.lock().unwrap();
        keys.get(&kyber_prekey_id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        let mut keys = self.kyber_pre_keys.lock().unwrap();
        keys.insert(kyber_prekey_id, record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<()> {
        // Pour l'instant on ne fait rien de spécial : la clé reste dans le store.
        let _ = kyber_prekey_id;
        Ok(())
    }
}

// ============================================================
// SessionStore
// ============================================================

#[async_trait(?Send)]
impl SessionStore for InMemoryStores {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>> {
        let key = Self::addr_key(address);
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(&key).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        let key = Self::addr_key(address);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(key, record.clone());
        Ok(())
    }
}

// ============================================================
// ProtocolStore (marqueur qui combine les 5)
// ============================================================

impl ProtocolStore for InMemoryStores {}
