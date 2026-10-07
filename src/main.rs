mod client;
mod config;
mod keys;
mod network;
mod notify;
mod persist;
mod relay;
mod session;
mod stores;
mod stores_wrappers;

use std::env;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::thread;

use client::Client;
use libsignal_protocol::*;
use network::{
    deserialize_bundle, serialize_bundle, KIND_BUNDLE, KIND_CIPHERTEXT, KIND_ERROR,
};
use stores::InMemoryStores;

fn usage() -> ! {
    eprintln!(
        "Usage:\n\
         \tkhimy relay <addr>\n\
         \tkhimy chat <relay_addr> <mon_nom> <dest>\n\
         \tkhimy connect\n\
         \tkhimy listen\n\
         \tkhimy config\n\
         \n\
         Exemple:\n\
         \tkhimy relay 0.0.0.0:9000\n\
         \tkhimy chat 127.0.0.1:9000 alice bob\n\
         \tkhimy connect\n\
         \tkhimy listen"
    );
    std::process::exit(2);
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "relay" => {
            if args.len() < 3 { usage(); }
            relay::run_server(&args[2])
        }
        "chat" => {
            if args.len() < 5 { usage(); }
            run_chat(&args[2], &args[3], &args[4])
        }
        "connect" => {
            let (addr, name, dest) = interactive_prompt()?;
            run_chat(&addr, &name, &dest)
        }
        "listen" => {
            let (addr, name) = interactive_prompt_listen()?;
            run_listen(&addr, &name)
        }
        "config" => {
            let path = config::path_string();
            let cfg = config::load();
            println!("Fichier de config : {}", path);
            println!("relay  = {}", cfg.relay.as_deref().unwrap_or("(non defini)"));
            println!("pseudo = {}", cfg.pseudo.as_deref().unwrap_or("(non defini)"));
            Ok(())
        }
        _ => usage(),
    }
}

fn interactive_prompt() -> io::Result<(String, String, String)> {
    let cfg = config::load();

    println!();
    println!("=== Khimy ===");
    println!();

    let default_relay = cfg.relay.as_deref().unwrap_or("127.0.0.1:9000");
    print!("Relay [{}] : ", default_relay);
    io::stdout().flush()?;
    let mut addr = String::new();
    io::stdin().read_line(&mut addr)?;
    let addr = addr.trim();
    let addr = if addr.is_empty() { default_relay } else { addr }.to_string();

    let default_pseudo = cfg.pseudo.as_deref().unwrap_or("");
    if default_pseudo.is_empty() {
        print!("Ton pseudo : ");
    } else {
        print!("Ton pseudo [{}] : ", default_pseudo);
    }
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim();
    let name = if name.is_empty() { default_pseudo } else { name }.to_string();
    if name.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "pseudo vide"));
    }

    print!("Destinataire : ");
    io::stdout().flush()?;
    let mut dest = String::new();
    io::stdin().read_line(&mut dest)?;
    let dest = dest.trim().to_string();
    if dest.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "destinataire vide"));
    }

    let new_cfg = config::Config {
        relay: Some(addr.clone()),
        pseudo: Some(name.clone()),
    };
    if let Err(e) = config::save(&new_cfg) {
        eprintln!("[config] avertissement: {}", e);
    }

    println!();
    Ok((addr, name, dest))
}

fn interactive_prompt_listen() -> io::Result<(String, String)> {
    let cfg = config::load();

    println!();
    println!("=== Khimy (listen) ===");
    println!();

    let default_relay = cfg.relay.as_deref().unwrap_or("127.0.0.1:9000");
    print!("Relay [{}] : ", default_relay);
    io::stdout().flush()?;
    let mut addr = String::new();
    io::stdin().read_line(&mut addr)?;
    let addr = addr.trim();
    let addr = if addr.is_empty() { default_relay } else { addr }.to_string();

    let default_pseudo = cfg.pseudo.as_deref().unwrap_or("");
    if default_pseudo.is_empty() {
        print!("Ton pseudo : ");
    } else {
        print!("Ton pseudo [{}] : ", default_pseudo);
    }
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim();
    let name = if name.is_empty() { default_pseudo } else { name }.to_string();
    if name.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "pseudo vide"));
    }

    let new_cfg = config::Config {
        relay: Some(addr.clone()),
        pseudo: Some(name.clone()),
    };
    if let Err(e) = config::save(&new_cfg) {
        eprintln!("[config] avertissement: {}", e);
    }

    println!();
    Ok((addr, name))
}

fn make_store(keys: &keys::GeneratedKeys) -> InMemoryStores {
    let store = InMemoryStores::new(keys.identity_key_pair.clone(), keys.registration_id);
    store
        .signed_pre_keys
        .lock()
        .unwrap()
        .insert(keys.signed_pre_key.0, keys.signed_pre_key.1.clone());
    store
        .kyber_pre_keys
        .lock()
        .unwrap()
        .insert(keys.kyber_pre_key.0, keys.kyber_pre_key.1.clone());
    {
        let mut pk = store.pre_keys.lock().unwrap();
        for (id, rec) in &keys.pre_keys {
            pk.insert(*id, rec.clone());
        }
    }
    store
}

fn build_bundle(keys: &keys::GeneratedKeys) -> PreKeyBundle {
    let pre = &keys.pre_keys[0];
    let spk = &keys.signed_pre_key;
    let kpk = &keys.kyber_pre_key;

    PreKeyBundle::new(
        keys.registration_id,
        DeviceId::new(1).unwrap(),
        Some((pre.0, pre.1.public_key().unwrap())),
        spk.0,
        spk.1.public_key().unwrap(),
        spk.1.signature().unwrap().to_vec(),
        kpk.0,
        kpk.1.public_key().unwrap(),
        kpk.1.signature().unwrap().to_vec(),
        *keys.identity_key_pair.identity_key(),
    )
    .expect("PreKeyBundle")
}

fn try_decrypt(
    store: &mut InMemoryStores,
    my_address: &ProtocolAddress,
    from_addr: &ProtocolAddress,
    payload: &[u8],
    rng: &mut (impl rand::Rng + rand::CryptoRng),
) -> Result<String, SignalProtocolError> {
    if let Ok(prekey) = PreKeySignalMessage::try_from(payload) {
        if let Ok(plain) = futures::executor::block_on(session::decrypt_prekey_message(
            store, my_address, from_addr, &prekey, rng,
        )) {
            return Ok(String::from_utf8_lossy(&plain).to_string());
        }
    }
    if let Ok(signal) = SignalMessage::try_from(payload) {
        let plain = futures::executor::block_on(session::decrypt_message(
            store, my_address, from_addr, &signal, rng,
        ))?;
        return Ok(String::from_utf8_lossy(&plain).to_string());
    }
    Err(SignalProtocolError::InvalidMessage(
        CiphertextMessageType::Whisper,
        "message illisible".to_string(),
    ))
}

fn run_chat(addr: &str, name: &str, dest: &str) -> io::Result<()> {
    let keys = keys::load_or_generate_keys(name).expect("keys");
    let store = make_store(&keys);

    persist::load_all(&store, name);

    let my_address = ProtocolAddress::new(name.to_string(), DeviceId::new(1).unwrap());
    let dest_address = ProtocolAddress::new(dest.to_string(), DeviceId::new(1).unwrap());

    let mut client = Client::connect(addr, name)?;
    println!("[{}] connecte a {}", name, addr);

    let bundle = build_bundle(&keys);
    let bundle_bytes = serialize_bundle(&bundle)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    client.publish_bundle(&bundle_bytes)?;
    println!("[{}] bundle publie", name);

    let bob_bundle = loop {
        client.request_bundle(dest)?;
        let (kind, from, payload) = client.recv()?;
        match kind {
            KIND_BUNDLE => {
                let bundle = deserialize_bundle(&payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
                println!("[{}] bundle de {} recu", name, from);
                break bundle;
            }
            KIND_ERROR => {
                let msg = String::from_utf8_lossy(&payload);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("relay: {}", msg),
                ));
            }
            KIND_CIPHERTEXT => {
                eprintln!("[{}] message recu avant bundle, ignore", name);
            }
            _ => {
                eprintln!("[{}] kind inconnu: 0x{:02x}", name, kind);
            }
        }
    };

    let mut rng = rand::rng();

    persist::save_all(&store, name);

    let store = Arc::new(Mutex::new(store));
    {
        let mut s = store.lock().unwrap();
        futures::executor::block_on(session::establish_session(
            &mut s,
            &my_address,
            &dest_address,
            &bob_bundle,
            &mut rng,
        ))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    }
    println!("[{}] session etablie avec {}", name, dest);

    {
        let s = store.lock().unwrap();
        persist::save_all(&s, name);
    }

    let mut stream_reader = client.stream.try_clone()?;
    let listen_store = Arc::clone(&store);
    let listen_name = name.to_string();
    let listen_my_address = my_address.clone();

    thread::spawn(move || {
        let mut rng = rand::rng();
        loop {
            match network::recv_frame(&mut stream_reader) {
                Ok(frame) => {
                    let (kind, from, payload) = match network::decode_envelope(&frame) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if kind == KIND_BUNDLE {
                        println!("[{}] bundle recu de {}", listen_name, from);
                    } else if kind == KIND_CIPHERTEXT {
                        let from_addr =
                            ProtocolAddress::new(from.clone(), DeviceId::new(1).unwrap());
                        let mut s = listen_store.lock().unwrap();
                        match try_decrypt(&mut s, &listen_my_address, &from_addr, &payload, &mut rng)
                        {
                            Ok(text) => {
                                notify::message(&from, &text);
                                println!("[{}] << {} : {}", listen_name, from, text);
                                persist::save_all(&s, &listen_name);
                            }
                            Err(e) => eprintln!("[{}] erreur: {:?}", listen_name, e),
                        }
                    }
                }
                Err(_) => {
                    eprintln!("[{}] thread d'ecoute termine", listen_name);
                    break;
                }
            }
        }
    });

    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("[{}] tape tes messages (Ctrl-D pour quitter)", name);
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let ct = {
            let mut s = store.lock().unwrap();
            futures::executor::block_on(session::encrypt_message(
                &mut s,
                &my_address,
                &dest_address,
                line.as_bytes(),
                &mut rng,
            ))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?
        };

        let bytes = ct.serialize();
        client.send_ciphertext(dest, &bytes)?;
        println!("[{}] -> {} ({} octets)", name, dest, bytes.len());
    }

    Ok(())
}

fn run_listen(addr: &str, name: &str) -> io::Result<()> {
    let keys = keys::load_or_generate_keys(name).expect("keys");
    let store = make_store(&keys);

    persist::load_all(&store, name);

    let my_address = ProtocolAddress::new(name.to_string(), DeviceId::new(1).unwrap());

    let mut client = Client::connect(addr, name)?;
    println!("[{}] connecte a {}", name, addr);

    let bundle = build_bundle(&keys);
    let bundle_bytes = serialize_bundle(&bundle)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    client.publish_bundle(&bundle_bytes)?;
    println!("[{}] bundle publie, en attente de messages...", name);

    let mut rng = rand::rng();
    let store = Arc::new(Mutex::new(store));
    let last_sender: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let mut stream_reader = client.stream.try_clone()?;
    let listen_store = Arc::clone(&store);
    let listen_name = name.to_string();
    let listen_my_address = my_address.clone();
    let listen_last = Arc::clone(&last_sender);

    thread::spawn(move || {
        let mut rng = rand::rng();
        loop {
            match network::recv_frame(&mut stream_reader) {
                Ok(frame) => {
                    let (kind, from, payload) = match network::decode_envelope(&frame) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if kind == KIND_ERROR {
                        eprintln!(
                            "[{}] relay: {}",
                            listen_name,
                            String::from_utf8_lossy(&payload)
                        );
                        break;
                    }
                    if kind == KIND_CIPHERTEXT {
                        let from_addr =
                            ProtocolAddress::new(from.clone(), DeviceId::new(1).unwrap());
                        let mut s = listen_store.lock().unwrap();
                        match try_decrypt(&mut s, &listen_my_address, &from_addr, &payload, &mut rng)
                        {
                            Ok(text) => {
                                notify::message(&from, &text);
                                println!();
                                println!("[{}] << {} : {}", listen_name, from, text);
                                println!(
                                    "[{}] /to {} pour repondre, ou tape ton message",
                                    listen_name, from
                                );
                                *listen_last.lock().unwrap() = Some(from.clone());
                                persist::save_all(&s, &listen_name);
                            }
                            Err(e) => eprintln!(
                                "[{}] erreur dechiffrement de {}: {:?}",
                                listen_name, from, e
                            ),
                        }
                    }
                }
                Err(_) => {
                    eprintln!("[{}] deconnecte du relay", listen_name);
                    break;
                }
            }
        }
    });

    println!();
    println!("[{}] Commandes:", name);
    println!("  /to <nom>  definit le destinataire courant");
    println!("  /quit      quitter");
    println!("  <texte>    envoyer au dernier expediteur (ou destinataire courant)");
    println!();

    let stdin = io::stdin();
    let mut current_dest: Option<String> = None;

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "/quit" {
            break;
        }

        if let Some(rest) = line.strip_prefix("/to ") {
            let rest = rest.trim();
            if rest.is_empty() {
                eprintln!("[{}] usage: /to <nom>", name);
                continue;
            }
            current_dest = Some(rest.to_string());
            println!("[{}] destinataire courant : {}", name, rest);
            continue;
        }

        let dest = if let Some(d) = &current_dest {
            d.clone()
        } else if let Some(d) = last_sender.lock().unwrap().clone() {
            d
        } else {
            eprintln!("[{}] pas de destinataire. Utilise /to <nom>", name);
            continue;
        };

        let dest_addr = ProtocolAddress::new(dest.clone(), DeviceId::new(1).unwrap());

        let ct_result = {
            let mut s = store.lock().unwrap();
            futures::executor::block_on(session::encrypt_message(
                &mut s,
                &my_address,
                &dest_addr,
                line.as_bytes(),
                &mut rng,
            ))
        };

        match ct_result {
            Ok(ct) => {
                let bytes = ct.serialize();
                client.send_ciphertext(&dest, &bytes)?;
                println!("[{}] -> {} ({} octets)", name, dest, bytes.len());
            }
            Err(e) => {
                eprintln!("[{}] erreur chiffrement vers {}: {:?}", name, dest, e);
                eprintln!(
                    "[{}] astuce: si tu n'as jamais recu de message de {}, utilise 'khimy connect' d'abord",
                    name, dest
                );
            }
        }
    }

    Ok(())
}
