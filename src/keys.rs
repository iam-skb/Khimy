//! Génération et persistance des clés Signal pour Khimy.

use libsignal_protocol::*;
use rand::Rng;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

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

/// Erreur custom pour la persistance.
#[derive(Debug)]
pub enum PersistError {
    Io(String),
    Signal(String),
}

impl From<std::io::Error> for PersistError {
    fn from(e: std::io::Error) -> Self {
        PersistError::Io(e.to_string())
    }
}

impl From<SignalProtocolError> for PersistError {
    fn from(e: SignalProtocolError) -> Self {
        PersistError::Signal(format!("{:?}", e))
    }
}

/// Renvoie le chemin du dossier ~/.khimy/<nom>/
fn khimy_user_dir(name: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut path = PathBuf::from(home);
    path.push(".khimy");
    path.push(name);
    path
}

/// Charge ou génère les clés pour un utilisateur donné.
pub fn load_or_generate_keys(name: &str) -> Result<GeneratedKeys, PersistError> {
    let dir = khimy_user_dir(name);
    let path = dir.join("keys.bin");

    if path.exists() {
        match load_keys(&path) {
            Ok(keys) => {
                println!("[{}] cles chargees depuis {:?}", name, path);
                Ok(keys)
            }
            Err(e) => {
                eprintln!("[{}] erreur chargement cles: {:?}", name, e);
                eprintln!("[{}] on regenere des cles", name);
                let keys = generate_all_keys()?;
                save_keys(&path, &keys)?;
                Ok(keys)
            }
        }
    } else {
        fs::create_dir_all(&dir)?;
        println!("[{}] generation de nouvelles cles", name);
        let keys = generate_all_keys()?;
        save_keys(&path, &keys)?;
        Ok(keys)
    }
}

/// Sauvegarde les clés dans un fichier binaire.
fn save_keys(path: &PathBuf, keys: &GeneratedKeys) -> Result<(), PersistError> {
    let mut file = fs::File::create(path)?;

    let id_public = keys.identity_key_pair.identity_key().serialize();
    let id_private = keys.identity_key_pair.private_key().serialize();
    write_bytes(&mut file, &id_public)?;
    write_bytes(&mut file, &id_private)?;

    file.write_all(&keys.registration_id.to_be_bytes())?;

    file.write_all(&u32::from(keys.signed_pre_key.0).to_be_bytes())?;
    let spk_bytes = keys.signed_pre_key.1.serialize()?;
    write_bytes(&mut file, &spk_bytes)?;

    file.write_all(&u32::from(keys.kyber_pre_key.0).to_be_bytes())?;
    let kpk_bytes = keys.kyber_pre_key.1.serialize()?;
    write_bytes(&mut file, &kpk_bytes)?;

    file.write_all(&(keys.pre_keys.len() as u32).to_be_bytes())?;
    for (id, record) in &keys.pre_keys {
        file.write_all(&u32::from(*id).to_be_bytes())?;
        let pk_bytes = record.serialize()?;
        write_bytes(&mut file, &pk_bytes)?;
    }

    Ok(())
}

fn write_bytes<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), PersistError> {
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

fn read_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>, PersistError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Charge les clés depuis un fichier binaire.
fn load_keys(path: &PathBuf) -> Result<GeneratedKeys, PersistError> {
    let mut file = fs::File::open(path)?;

    let id_public = read_bytes(&mut file)?;
    let id_private = read_bytes(&mut file)?;
    let identity_key = IdentityKey::decode(&id_public)
        .map_err(|e| PersistError::Signal(format!("identity key: {:?}", e)))?;
    let private_key = PrivateKey::deserialize(&id_private)
        .map_err(|e| PersistError::Signal(format!("private key: {:?}", e)))?;
    let identity_key_pair = IdentityKeyPair::new(identity_key, private_key);

    let mut reg_buf = [0u8; 4];
    file.read_exact(&mut reg_buf)?;
    let registration_id = u32::from_be_bytes(reg_buf);

    let mut spk_id_buf = [0u8; 4];
    file.read_exact(&mut spk_id_buf)?;
    let spk_id = SignedPreKeyId::from(u32::from_be_bytes(spk_id_buf));
    let spk_bytes = read_bytes(&mut file)?;
    let spk_record = SignedPreKeyRecord::deserialize(&spk_bytes)
        .map_err(|e| PersistError::Signal(format!("spk: {:?}", e)))?;

    let mut kpk_id_buf = [0u8; 4];
    file.read_exact(&mut kpk_id_buf)?;
    let kpk_id = KyberPreKeyId::from(u32::from_be_bytes(kpk_id_buf));
    let kpk_bytes = read_bytes(&mut file)?;
    let kpk_record = KyberPreKeyRecord::deserialize(&kpk_bytes)
        .map_err(|e| PersistError::Signal(format!("kpk: {:?}", e)))?;

    let mut num_buf = [0u8; 4];
    file.read_exact(&mut num_buf)?;
    let num_pre_keys = u32::from_be_bytes(num_buf);
    let mut pre_keys = Vec::with_capacity(num_pre_keys as usize);
    for _ in 0..num_pre_keys {
        let mut pk_id_buf = [0u8; 4];
        file.read_exact(&mut pk_id_buf)?;
        let pk_id = PreKeyId::from(u32::from_be_bytes(pk_id_buf));
        let pk_bytes = read_bytes(&mut file)?;
        let pk_record = PreKeyRecord::deserialize(&pk_bytes)
            .map_err(|e| PersistError::Signal(format!("pk: {:?}", e)))?;
        pre_keys.push((pk_id, pk_record));
    }

    Ok(GeneratedKeys {
        identity_key_pair,
        registration_id,
        signed_pre_key: (spk_id, spk_record),
        kyber_pre_key: (kpk_id, kpk_record),
        pre_keys,
    })
}

/// Génère un ensemble complet de clés Signal.
pub fn generate_all_keys() -> Result<GeneratedKeys, PersistError> {
    let mut rng = rand::rng();

    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let registration_id = rng.random_range(1..=16380);

    let signed_pre_key_id = SignedPreKeyId::from(1u32);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut rng)
        .map_err(|e| PersistError::Signal(format!("sig spk: {:?}", e)))?;
    let signed_pre_key_record = SignedPreKeyRecord::new(
        signed_pre_key_id,
        Timestamp::from_epoch_millis(now_millis()),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );

    let kyber_pre_key_id = KyberPreKeyId::from(1u32);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let kyber_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), &mut rng)
        .map_err(|e| PersistError::Signal(format!("sig kpk: {:?}", e)))?;
    let kyber_pre_key_record = KyberPreKeyRecord::new(
        kyber_pre_key_id,
        Timestamp::from_epoch_millis(now_millis()),
        &kyber_pre_key_pair,
        &kyber_pre_key_signature,
    );

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
