//! Persistance disque des sessions Signal et des identités distantes.
//!
//! Stocke les SessionRecord et IdentityKey dans ~/.khimy/<nom>/.

use crate::stores::InMemoryStores;
use libsignal_protocol::*;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

fn khimy_dir(name: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut p = PathBuf::from(home);
    p.push(".khimy");
    p.push(name);
    p
}

fn sessions_path(name: &str) -> PathBuf {
    khimy_dir(name).join("sessions.bin")
}

fn identities_path(name: &str) -> PathBuf {
    khimy_dir(name).join("identities.bin")
}

fn write_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(&(bytes.len() as u32).to_be_bytes())?;
    w.write_all(bytes)?;
    Ok(())
}

fn read_bytes<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Sauvegarde toutes les sessions du store dans le fichier.
pub fn save_sessions(store: &InMemoryStores, name: &str) -> io::Result<()> {
    let path = sessions_path(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let sessions = store.sessions.lock().unwrap();
    let mut file = fs::File::create(&path)?;

    file.write_all(&(sessions.len() as u32).to_be_bytes())?;

    for (key, record) in sessions.iter() {
        write_bytes(&mut file, key.as_bytes())?;
        let bytes = record
            .serialize()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        write_bytes(&mut file, &bytes)?;
    }

    Ok(())
}

/// Charge les sessions depuis le fichier et les met dans le store.
pub fn load_sessions(store: &InMemoryStores, name: &str) -> io::Result<()> {
    let path = sessions_path(name);
    if !path.exists() {
        return Ok(());
    }

    let mut file = fs::File::open(&path)?;

    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf);

    let mut sessions = store.sessions.lock().unwrap();

    for _ in 0..count {
        let key_bytes = read_bytes(&mut file)?;
        let key = String::from_utf8(key_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cle non-utf8"))?;

        let record_bytes = read_bytes(&mut file)?;
        let record = SessionRecord::deserialize(&record_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;

        sessions.insert(key, record);
    }

    println!("[{}] {} sessions chargees", name, count);
    Ok(())
}

/// Sauvegarde toutes les identités distantes du store dans le fichier.
pub fn save_identities(store: &InMemoryStores, name: &str) -> io::Result<()> {
    let path = identities_path(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let identities = store.identities.lock().unwrap();
    let mut file = fs::File::create(&path)?;

    file.write_all(&(identities.len() as u32).to_be_bytes())?;

    for (key, identity) in identities.iter() {
        write_bytes(&mut file, key.as_bytes())?;
        let bytes = identity.serialize();
        write_bytes(&mut file, &bytes)?;
    }

    Ok(())
}

/// Charge les identités depuis le fichier et les met dans le store.
pub fn load_identities(store: &InMemoryStores, name: &str) -> io::Result<()> {
    let path = identities_path(name);
    if !path.exists() {
        return Ok(());
    }

    let mut file = fs::File::open(&path)?;

    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf);

    let mut identities = store.identities.lock().unwrap();

    for _ in 0..count {
        let key_bytes = read_bytes(&mut file)?;
        let key = String::from_utf8(key_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cle non-utf8"))?;

        let identity_bytes = read_bytes(&mut file)?;
        let identity = IdentityKey::decode(&identity_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;

        identities.insert(key, identity);
    }

    println!("[{}] {} identites chargees", name, count);
    Ok(())
}

/// Helper : sauvegarde sessions + identités.
pub fn save_all(store: &InMemoryStores, name: &str) {
    if let Err(e) = save_sessions(store, name) {
        eprintln!("[{}] erreur sauvegarde sessions: {}", name, e);
    }
    if let Err(e) = save_identities(store, name) {
        eprintln!("[{}] erreur sauvegarde identites: {}", name, e);
    }
}

/// Helper : charge sessions + identités.
pub fn load_all(store: &InMemoryStores, name: &str) {
    if let Err(e) = load_sessions(store, name) {
        eprintln!("[{}] erreur chargement sessions: {}", name, e);
    }
    if let Err(e) = load_identities(store, name) {
        eprintln!("[{}] erreur chargement identites: {}", name, e);
    }
}
