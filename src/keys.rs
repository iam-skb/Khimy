//! Génération des clés Signal pour Khimy.

use libsignal_protocol::*;
use rand::Rng;

/// Nombre de one-time pre-keys à générer par défaut.
pub const DEFAULT_PRE_KEY_COUNT: u32 = 100;

/// Ensemble de clés générées au premier lancement de Khimy.
pub struct GeneratedKeys {
    pub identity_key_pair: IdentityKeyPair,
    pub registration_id: u32,
    pub signed_pre_key: (SignedPreKeyId, SignedPreKeyRecord),
    pub kyber_pre_key: (KyberPreKeyId, KyberPreKeyRecord),
    pub pre_keys: Vec<(PreKeyId, PreKeyRecord)>,
}

/// Génère un ensemble complet de clés Signal.
pub fn generate_all_keys() -> Result<GeneratedKeys, SignalProtocolError> {
    let mut rng = rand::rng();

    // 1. Identity Key Pair (X25519)
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);

    // 2. Registration ID (u32 entre 1 et 16380)
    let registration_id = rng.random_range(1..=16380);

    // 3. Signed Pre-Key
    let signed_pre_key_id = SignedPreKeyId::from(1u32);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut rng)?;
    let signed_pre_key_record = SignedPreKeyRecord::new(
        signed_pre_key_id,
        Timestamp::from_epoch_millis(now_millis()),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );

    // 4. Kyber Pre-Key (post-quantique)
    let kyber_pre_key_id = KyberPreKeyId::from(1u32);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let kyber_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), &mut rng)?;
    let kyber_pre_key_record = KyberPreKeyRecord::new(
        kyber_pre_key_id,
        Timestamp::from_epoch_millis(now_millis()),
        &kyber_pre_key_pair,
        &kyber_pre_key_signature,
    );

    // 5. One-Time Pre-Keys
    let mut pre_keys = Vec::with_capacity(DEFAULT_PRE_KEY_COUNT as usize);
    for i in 1..=DEFAULT_PRE_KEY_COUNT {
        let pre_key_id = PreKeyId::from(i);
        let pre_key_pair = KeyPair::generate(&mut rng);
        let pre_key_record = PreKeyRecord::new(pre_key_id, &pre_key_pair);
        pre_keys.push((pre_key_id, pre_key_record));
    }

    Ok(GeneratedKeys {
        identity_key_pair,
        registration_id,
        signed_pre_key: (signed_pre_key_id, signed_pre_key_record),
        kyber_pre_key: (kyber_pre_key_id, kyber_pre_key_record),
        pre_keys,
    })
}

/// Timestamp Unix en millisecondes.
fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
