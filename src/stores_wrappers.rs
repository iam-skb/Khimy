//! Wrappers individuels autour des HashMaps de InMemoryStores.
//!
//! libsignal demande un `&mut dyn Trait` par store, pas un objet combiné.
//! Ces wrappers exposent chaque HashMap sous forme d'un store indépendant.

use async_trait::async_trait;
use libsignal_protocol::*;

use std::collections::HashMap;
use std::sync::Mutex;

type Result<T> = std::result::Result<T, SignalProtocolError>;

pub fn addr_key(address: &ProtocolAddress) -> String {
    format!("{}.{}", address.name(), u32::from(address.device_id()))
}

// ─── Identity Store ─────────────────────────────────────────

pub struct IdentityStoreView {
    pub identity_key_pair: IdentityKeyPair,
    pub registration_id: u32,
    pub identities: Mutex<HashMap<String, IdentityKey>>,
}

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityStoreView {
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
        let key = addr_key(address);
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
        let key = addr_key(address);
        let ids = self.identities.lock().unwrap();
        Ok(ids.get(&key).map(|k| k == identity).unwrap_or(true))
    }
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        let key = addr_key(address);
        let ids = self.identities.lock().unwrap();
        Ok(ids.get(&key).copied())
    }
}

// ─── PreKey Store ───────────────────────────────────────────

pub struct PreKeyStoreView {
    pub pre_keys: Mutex<HashMap<PreKeyId, PreKeyRecord>>,
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeyStoreView {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        let keys = self.pre_keys.lock().unwrap();
        keys.get(&prekey_id).cloned()
            .ok_or_else(|| SignalProtocolError::InvalidPreKeyId)
    }
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.pre_keys.lock().unwrap().insert(prekey_id, record.clone());
        Ok(())
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        self.pre_keys.lock().unwrap().remove(&prekey_id);
        Ok(())
    }
}

// ─── Signed PreKey Store ────────────────────────────────────

pub struct SignedPreKeyStoreView {
    pub signed_pre_keys: Mutex<HashMap<SignedPreKeyId, SignedPreKeyRecord>>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeyStoreView {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord> {
        let keys = self.signed_pre_keys.lock().unwrap();
        keys.get(&signed_prekey_id).cloned()
            .ok_or_else(|| SignalProtocolError::InvalidSignedPreKeyId)
    }
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.signed_pre_keys.lock().unwrap().insert(signed_prekey_id, record.clone());
        Ok(())
    }
}

// ─── Kyber PreKey Store ─────────────────────────────────────

pub struct KyberPreKeyStoreView {
    pub kyber_pre_keys: Mutex<HashMap<KyberPreKeyId, KyberPreKeyRecord>>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeyStoreView {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord> {
        let keys = self.kyber_pre_keys.lock().unwrap();
        keys.get(&kyber_prekey_id).cloned()
            .ok_or_else(|| SignalProtocolError::InvalidKyberPreKeyId)
    }
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.kyber_pre_keys.lock().unwrap().insert(kyber_prekey_id, record.clone());
        Ok(())
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<()> {
        Ok(())
    }
}

// ─── Session Store ──────────────────────────────────────────

pub struct SessionStoreView {
    pub sessions: Mutex<HashMap<String, SessionRecord>>,
}

#[async_trait(?Send)]
impl SessionStore for SessionStoreView {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let key = addr_key(address);
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(&key).cloned())
    }
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        let key = addr_key(address);
        self.sessions.lock().unwrap().insert(key, record.clone());
        Ok(())
    }
}
