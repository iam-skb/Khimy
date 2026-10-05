mod client;
mod keys;
mod network;
mod relay;
mod session;
mod stores;
mod stores_wrappers;

use std::env;
use std::io::{self, BufRead};

use client::Client;
use libsignal_protocol::*;
use network::{deserialize_bundle, serialize_bundle, KIND_BUNDLE, KIND_CIPHERTEXT};
use stores::InMemoryStores;

fn usage() -> ! {
    eprintln!(
        "Usage:\n\
         \tkhimy relay <addr>\n\
         \tkhimy listen <addr> <nom>\n\
         \tkhimy connect <addr> <nom> <dest>\n\
         \n\
         Exemple:\n\
         \tkhimy relay 127.0.0.1:9000\n\
         \tkhimy listen 127.0.0.1:9000 bob\n\
         \tkhimy connect 127.0.0.1:9000 alice bob"
    );
    std::process::exit(2);
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage();
    }

    match args[1].as_str() {
        "relay" => relay::run_server(&args[2]),
        "listen" => {
            if args.len() < 4 { usage(); }
            run_listen(&args[2], &args[3])
        }
        "connect" => {
            if args.len() < 5 { usage(); }
            run_connect(&args[2], &args[3], &args[4])
        }
        _ => usage(),
    }
}

fn make_store(keys: &keys::GeneratedKeys) -> InMemoryStores {
    let store = InMemoryStores::new(keys.identity_key_pair.clone(), keys.registration_id);
    store.signed_pre_keys.lock().unwrap()
        .insert(keys.signed_pre_key.0, keys.signed_pre_key.1.clone());
    store.kyber_pre_keys.lock().unwrap()
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

fn run_listen(addr: &str, name: &str) -> io::Result<()> {
    let mut rng = rand::rng();
    let keys = keys::generate_all_keys().expect("keys");
    let mut store = make_store(&keys);

    let bundle = build_bundle(&keys);
    let bundle_bytes = serialize_bundle(&bundle)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    let mut client = Client::connect(addr, name)?;
    client.publish_bundle(&bundle_bytes)?;
    println!("[{}] connecte a {}, bundle publie", name, addr);

    let my_address = ProtocolAddress::new(name.to_string(), DeviceId::new(1).unwrap());

    loop {
        let (kind, from, payload) = client.recv()?;
        match kind {
            KIND_BUNDLE => println!("[{}] bundle recu de {}", name, from),

            KIND_CIPHERTEXT => {
                let from_addr = ProtocolAddress::new(from.clone(), DeviceId::new(1).unwrap());

                let result = if let Ok(prekey) = PreKeySignalMessage::try_from(payload.as_slice()) {
                    futures::executor::block_on(session::decrypt_prekey_message(
                        &mut store, &my_address, &from_addr, &prekey, &mut rng,
                    ))
                    .or_else(|_| {
                        let signal = SignalMessage::try_from(payload.as_slice())
                            .map_err(|e| SignalProtocolError::InvalidMessage(CiphertextMessageType::Whisper, format!("{:?}", e)))?;
                        futures::executor::block_on(session::decrypt_message(
                            &mut store, &my_address, &from_addr, &signal, &mut rng,
                        ))
                    })
                } else if let Ok(signal) = SignalMessage::try_from(payload.as_slice()) {
                    futures::executor::block_on(session::decrypt_message(
                        &mut store, &my_address, &from_addr, &signal, &mut rng,
                    ))
                } else {
                    eprintln!("[{}] message illisible", name);
                    continue;
                };

                match result {
                    Ok(plain) => println!("[{}] << {} : {}", name, from, String::from_utf8_lossy(&plain)),
                    Err(e) => eprintln!("[{}] erreur dechiffrement: {:?}", name, e),
                }
            }
            _ => {}
        }
    }
}

fn run_connect(addr: &str, name: &str, dest: &str) -> io::Result<()> {
    let mut rng = rand::rng();
    let keys = keys::generate_all_keys().expect("keys");
    let mut store = make_store(&keys);

    let my_address = ProtocolAddress::new(name.to_string(), DeviceId::new(1).unwrap());
    let dest_address = ProtocolAddress::new(dest.to_string(), DeviceId::new(1).unwrap());

    let mut client = Client::connect(addr, name)?;
    println!("[{}] connecte a {}, demande le bundle de {}", name, addr, dest);

    client.request_bundle(dest)?;
    let (kind, _from, bundle_bytes) = client.recv()?;
    if kind != KIND_BUNDLE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bundle attendu"));
    }
    let bob_bundle = deserialize_bundle(&bundle_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
    println!("[{}] bundle de {} recu", name, dest);

    futures::executor::block_on(session::establish_session(
        &mut store, &my_address, &dest_address, &bob_bundle, &mut rng,
    ))
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    println!("[{}] session etablie avec {}", name, dest);

    println!("[{}] tape tes messages (Ctrl-D pour quitter)", name);
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }

        let ct = futures::executor::block_on(session::encrypt_message(
            &mut store, &my_address, &dest_address, line.as_bytes(), &mut rng,
        ))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

        let bytes = ct.serialize();
        client.send_ciphertext(dest, &bytes)?;
        println!("[{}] -> {} ({} octets)", name, dest, bytes.len());
    }

    Ok(())
}
