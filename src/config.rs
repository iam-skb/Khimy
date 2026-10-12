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

/// Parse un contenu de fichier de config.
/// Extrait pour etre testable sans toucher au disque.
pub(crate) fn parse_config(content: &str) -> Config {
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

pub fn load() -> Config {
    let path = config_path();
    if !path.exists() {
        return Config::default();
    }
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Config::default(),
    };
    parse_config(&content)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let cfg = parse_config("");
        assert!(cfg.relay.is_none());
        assert!(cfg.pseudo.is_none());
    }

    #[test]
    fn parse_basic() {
        let cfg = parse_config("relay=127.0.0.1:9000\npseudo=alice\n");
        assert_eq!(cfg.relay.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(cfg.pseudo.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_with_quotes() {
        let cfg = parse_config("relay=\"127.0.0.1:9000\"\npseudo=\"alice\"\n");
        assert_eq!(cfg.relay.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(cfg.pseudo.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_with_comments() {
        let cfg = parse_config("# comment\nrelay=x:1\n\n# another\npseudo=y\n");
        assert_eq!(cfg.relay.as_deref(), Some("x:1"));
        assert_eq!(cfg.pseudo.as_deref(), Some("y"));
    }

    #[test]
    fn parse_unknown_keys_ignored() {
        let cfg = parse_config("relay=x\nfoo=bar\npseudo=y\n");
        assert_eq!(cfg.relay.as_deref(), Some("x"));
        assert_eq!(cfg.pseudo.as_deref(), Some("y"));
    }

    #[test]
    fn parse_whitespace_around() {
        let cfg = parse_config("  relay = x:1  \n  pseudo = y  \n");
        assert_eq!(cfg.relay.as_deref(), Some("x:1"));
        assert_eq!(cfg.pseudo.as_deref(), Some("y"));
    }
}
