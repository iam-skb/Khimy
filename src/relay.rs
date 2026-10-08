//! Serveur relay : route les enveloppes. Sert aussi d'annuaire de bundles.
//! Stocke les messages pour les utilisateurs hors-ligne.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::network::{
    decode_envelope, encode_envelope, recv_frame, send_frame, KIND_BUNDLE,
    KIND_BUNDLE_REQUEST, KIND_CIPHERTEXT, KIND_ERROR, KIND_FETCH_PENDING,
};

const MAX_PENDING_PER_USER: usize = 100;
const PENDING_TTL_SECS: u64 = 7 * 24 * 3600; // 7 jours

struct PendingMessage {
    from: String,
    payload: Vec<u8>,
    timestamp: u64,
}

struct State {
    clients: HashMap<String, TcpStream>,
    bundles: HashMap<String, Vec<u8>>,
    waiting: Vec<(String, String)>,
    pending: HashMap<String, Vec<PendingMessage>>,
}

type Shared = Arc<Mutex<State>>;

struct ClientGuard {
    name: String,
    state: Shared,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            st.clients.remove(&self.name);
            println!("[relay] - {} deconnecte", self.name);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run_server(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("[relay] ecoute sur {}", addr);

    let state: Shared = Arc::new(Mutex::new(State {
        clients: HashMap::new(),
        bundles: HashMap::new(),
        waiting: Vec::new(),
        pending: HashMap::new(),
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

    {
        let st = state.lock().unwrap();
        if st.clients.contains_key(&name) {
            eprintln!("[relay] pseudo deja pris: {}", name);
            drop(st);
            let err_env = encode_envelope(KIND_ERROR, &name, b"pseudo deja pris");
            let _ = send_frame(&mut stream, &err_env);
            let _ = stream.shutdown(Shutdown::Write);
            std::thread::sleep(std::time::Duration::from_millis(500));
            return Ok(());
        }
    }

    println!("[relay] + {} connecte", name);

    let writer = stream.try_clone()?;
    state.lock().unwrap().clients.insert(name.clone(), writer);

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
                let bundle = state.lock().unwrap().bundles.get(&dest).cloned();
                if let Some(bytes) = bundle {
                    let env = encode_envelope(KIND_BUNDLE, &dest, &bytes);
                    let mut st = state.lock().unwrap();
                    if let Some(w) = st.clients.get_mut(&name) {
                        let _ = send_frame(w, &env);
                    }
                } else {
                    eprintln!("[relay] bundle inconnu: {}, on met en attente", dest);
                    state
                        .lock()
                        .unwrap()
                        .waiting
                        .push((name.clone(), dest.clone()));
                }
            }

            KIND_BUNDLE => {
                let mut st = state.lock().unwrap();

                // Sauvegarde le bundle
                st.bundles.insert(name.clone(), payload);

                // Notifie les clients en attente
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
                        let env = encode_envelope(KIND_BUNDLE, &name, &bundle);
                        if let Some(w) = st.clients.get_mut(requester) {
                            let _ = send_frame(w, &env);
                            println!("[relay] bundle de {} envoye a {}", name, requester);
                        }
                    }
                }
            }

            KIND_CIPHERTEXT => {
                let mut st = state.lock().unwrap();
                if let Some(target) = st.clients.get_mut(&dest) {
                    // Destinataire connecte : envoi direct
                    let env = encode_envelope(KIND_CIPHERTEXT, &name, &payload);
                    if send_frame(target, &env).is_err() {
                        st.clients.remove(&dest);
                    }
                } else {
                    // Destinataire hors-ligne : stocke pour plus tard
                    let now = now_secs();
                    let entry = st.pending.entry(dest.clone()).or_default();
                    entry.retain(|m| now.saturating_sub(m.timestamp) < PENDING_TTL_SECS);
                    if entry.len() < MAX_PENDING_PER_USER {
                        entry.push(PendingMessage {
                            from: name.clone(),
                            payload: payload.clone(),
                            timestamp: now,
                        });
                        println!(
                            "[relay] message de {} stocke pour {} ({} en attente)",
                            name,
                            dest,
                            entry.len()
                        );
                    } else {
                        eprintln!(
                            "[relay] boite pleine pour {} ({} max), message de {} rejete",
                            dest, MAX_PENDING_PER_USER, name
                        );
                    }
                }
            }

            KIND_FETCH_PENDING => {
                // Le client demande ses messages en attente
                let msgs = state.lock().unwrap().pending.remove(&name);
                if let Some(list) = msgs {
                    let count = list.len();
                    let mut st = state.lock().unwrap();
                    if let Some(w) = st.clients.get_mut(&name) {
                        for msg in list {
                            let env =
                                encode_envelope(KIND_CIPHERTEXT, &msg.from, &msg.payload);
                            let _ = send_frame(w, &env);
                        }
                    }
                    if count > 0 {
                        println!("[relay] {} message(s) livre(s) a {}", count, name);
                    }
                }
            }

            _ => eprintln!("[relay] kind inconnu: 0x{:02x}", kind),
        }
    }

    Ok(())
}
