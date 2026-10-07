//! Serveur relay : route les enveloppes. Sert aussi d'annuaire de 
bundles.

use std::collections::HashMap;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::network::{
    decode_envelope, encode_envelope, recv_frame, send_frame, KIND_BUNDLE,
    KIND_BUNDLE_REQUEST, KIND_CIPHERTEXT,
};

struct State {
    clients: HashMap<String, TcpStream>,
    bundles: HashMap<String, Vec<u8>>,
    waiting: Vec<(String, String)>,
}

type Shared = Arc<Mutex<State>>;

/// Guard RAII : nettoie automatiquement le client à la sortie de 
`handle_client`,
/// même en cas de panic. Évite les fuites de pseudos dans `clients`.
struct ClientGuard {
    name: String,
    state: Shared,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            st.clients.remove(&self.name);
            println!("[relay] - {} deconnecte (cleanup auto)", self.name);
        }
    }
}

pub fn run_server(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("[relay] ecoute sur {}", addr);

    let state: Shared = Arc::new(Mutex::new(State {
        clients: HashMap::new(),
        bundles: HashMap::new(),
        waiting: Vec::new(),
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
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "nom 
non-utf8"))?;

    // Vérifie que le pseudo n'est pas déjà pris
    {
        let st = state.lock().unwrap();
        if st.clients.contains_key(&name) {
            eprintln!("[relay] pseudo deja pris: {}", name);
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "pseudo deja pris",
            ));
        }
    }

    println!("[relay] + {} connecte", name);

    let writer = stream.try_clone()?;
    state.lock().unwrap().clients.insert(name.clone(), writer);

    // Guard RAII : nettoie automatiquement le pseudo à la sortie,
    // même en cas de panic dans la boucle ci-dessous.
    let _guard = ClientGuard {
        name: name.clone(),
        state: Arc::clone(&state),
    };

    loop {
        let frame = match recv_frame(&mut stream) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        let (kind, dest, payload) = decode_envelope(&frame)?;
        println!(
            "[relay] {} -> {} (kind=0x{:02x}, {} octets)",
            name,
            dest,
            kind,
            payload.len()
        );

        match kind {
            KIND_BUNDLE_REQUEST => {
                let bundle = 
state.lock().unwrap().bundles.get(&dest).cloned();
                if let Some(bytes) = bundle {
                    let env = encode_envelope(KIND_BUNDLE, &dest, &bytes);
                    let mut st = state.lock().unwrap();
                    if let Some(w) = st.clients.get_mut(&name) {
                        let _ = send_frame(w, &env);
                    }
                } else {
                    eprintln!("[relay] bundle inconnu: {}, on met en 
attente", dest);
                    state
                        .lock()
                        .unwrap()
                        .waiting
                        .push((name.clone(), dest.clone()));
                }
            }

            KIND_BUNDLE => {
                state.lock().unwrap().bundles.insert(name.clone(), 
payload);

                let mut st = state.lock().unwrap();
                let mut still_waiting = Vec::new();
                let mut to_notify = Vec::new();

                for (requester, target) in st.waiting.drain(..) {
                    if target == name {
                        to_notify.push(requester);
                    } else {
                        still_waiting.push((requester, target));
                    }
                }
                st.waiting = still_waiting;

                for requester in &to_notify {
                    if let Some(bundle) = st.bundles.get(&name).cloned() {
                        let env = encode_envelope(KIND_BUNDLE, &name, 
&bundle);
                        if let Some(w) = st.clients.get_mut(requester) {
                            let _ = send_frame(w, &env);
                            println!("[relay] bundle de {} envoye a {}", 
name, requester);
                        }
                    }
                }
            }

            KIND_CIPHERTEXT => {
                let mut st = state.lock().unwrap();
                if let Some(target) = st.clients.get_mut(&dest) {
                    let env = encode_envelope(KIND_CIPHERTEXT, &name, 
&payload);
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

    Ok(())
}
