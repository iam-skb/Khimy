//! Serveur relay : route les enveloppes. Sert aussi d'annuaire de bundles.

use std::collections::HashMap;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::network::{
    decode_envelope, encode_envelope, recv_frame, send_frame, KIND_BUNDLE, KIND_BUNDLE_REQUEST,
    KIND_CIPHERTEXT,
};

struct State {
    clients: HashMap<String, TcpStream>,
    bundles: HashMap<String, Vec<u8>>,
}

type Shared = Arc<Mutex<State>>;

pub fn run_server(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("[relay] ecoute sur {}", addr);

    let state: Shared = Arc::new(Mutex::new(State {
        clients: HashMap::new(),
        bundles: HashMap::new(),
    }));

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(e) = handle_client(s, st) {
                        eprintln!("[relay] client deconnecte: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[relay] accept error: {}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, state: Shared) -> io::Result<()> {
    let name = String::from_utf8(recv_frame(&mut stream)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "nom non-utf8"))?;
    println!("[relay] + {} connecte", name);

    let writer = stream.try_clone()?;
    state.lock().unwrap().clients.insert(name.clone(), writer);

    loop {
        let frame = match recv_frame(&mut stream) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        let (kind, dest, payload) = decode_envelope(&frame)?;
        println!("[relay] {} -> {} (kind=0x{:02x}, {} octets)", name, dest, kind, payload.len());

        match kind {
            KIND_BUNDLE_REQUEST => {
                let bundle = state.lock().unwrap().bundles.get(&dest).cloned();
                if let Some(bytes) = bundle {
                    let env = encode_envelope(KIND_BUNDLE, &dest, &bytes);
                    let mut st = state.lock().unwrap();
                    if let Some(w) = st.clients.get_mut(&name) {
                        let _ = send_frame(w, &env);
                    }
                } else {
                    eprintln!("[relay] bundle inconnu: {}", dest);
                }
            }

            KIND_BUNDLE => {
                state.lock().unwrap().bundles.insert(name.clone(), payload);
                println!("[relay] bundle publie par {}", name);
            }

            KIND_CIPHERTEXT => {
                let mut st = state.lock().unwrap();
                if let Some(target) = st.clients.get_mut(&dest) {
                    let env = encode_envelope(KIND_CIPHERTEXT, &name, &payload);
                    if send_frame(target, &env).is_err() {
                        st.clients.remove(&dest);
                    }
                } else {
                    eprintln!("[relay] destinataire inconnu: {}", dest);
                }
            }

            _ => eprintln!("[relay] kind inconnu: 0x{:02x}", kind),
        }
    }

    state.lock().unwrap().clients.remove(&name);
    println!("[relay] - {} deconnecte", name);
    Ok(())
}
