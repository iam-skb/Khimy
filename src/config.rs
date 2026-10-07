//! Gestion du fichier de configuration ~/.khimy/config.toml

use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Default)]
pub struct Config {
    pub relay: Option<String>,
    pub pseudo: Option<String>,
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let mut p = PathBuf::from(home);
    p.push(".khimy");
    p.push("config.toml");
    p
}

pub fn load() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Config::default(),
    };
    let mut cfg = Config::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "relay" => cfg.relay = Some(value.to_string()),
                "pseudo" => cfg.pseudo = Some(value.to_string()),
                _ => {}
            }
        }
    }
    cfg
}

pub fn save(cfg: &Config) -> io::Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::from("# Fichier de configuration Khimy\n");
    if let Some(relay) = &cfg.relay {
        out.push_str(&format!("relay={}\n", relay));
    }
    if let Some(pseudo) = &cfg.pseudo {
        out.push_str(&format!("pseudo={}\n", pseudo));
    }
    fs::write(&path, out)
}

pub fn path_string() -> String {
    config_path().display().to_string()
}
