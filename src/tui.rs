//! Interface TUI (Ratatui) pour Khimy — thème rose pastel, connectée au relay.

use std::io::{self, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

use libsignal_protocol::*;

use crate::client::Client;
use crate::config;
use crate::keys;
use crate::network::{
    self, deserialize_bundle, serialize_bundle, KIND_BUNDLE, KIND_CIPHERTEXT, KIND_ERROR,
};
use crate::persist;
use crate::session;
use crate::stores::InMemoryStores;

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

const PINK:        Color = Color::Indexed(218);
const PINK_BRIGHT: Color = Color::Indexed(224);
const PINK_DIM:    Color = Color::Indexed(175);
const PINK_DEEP:   Color = Color::Indexed(132);
const MUTED:       Color = Color::Indexed(139);
const TEXT:        Color = Color::Indexed(255);
const BG:          Color = Color::Indexed(233);

const BANNER: &[&str] = &[
    " ██╗  ██╗ ██╗  ██╗ ██╗ ███╗   ███╗ ██╗   ██╗",
    " ██║ ██╔╝ ██║  ██║ ██║ ████╗ ████║ ╚██╗ ██╔╝",
    " █████╔╝  ███████║ ██║ ██╔████╔██║  ╚████╔╝ ",
    " ██╔═██╗  ██╔══██║ ██║ ██║╚██╔╝██║   ╚██╔╝  ",
    " ██║  ██╗ ██║  ██║ ██║ ██║ ╚═╝ ██║    ██║   ",
    " ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝ ╚═╝     ╚═╝    ╚═╝   ",
];

struct Message {
    time: String,
    from: String,
    text: String,
    kind: MsgKind,
}

enum MsgKind {
    System,
    Mine,
    Other,
    Banner,
}

struct App {
    pseudo: String,
    relay: String,
    dest: String,
    messages: Vec<Message>,
    input: String,
    should_quit: bool,
    pending_switch: Option<String>,
}

impl App {
    fn new(pseudo: String, relay: String, dest: String) -> Self {
        Self {
            pseudo,
            relay,
            dest,
            messages: vec![
                Message {
                    time: now_short(),
                    from: String::new(),
                    text: "session chiffree — x3dh + double ratchet + ml-kem-1024".to_string(),
                    kind: MsgKind::System,
                },
                Message {
                    time: now_short(),
                    from: String::new(),
                    text: "/help pour les commandes, ctrl+c pour quitter".to_string(),
                    kind: MsgKind::System,
                },
            ],
            input: String::new(),
            should_quit: false,
            pending_switch: None,
        }
    }

    fn push(&mut self, kind: MsgKind, from: &str, text: &str) {
        self.messages.push(Message {
            time: now_short(),
            from: from.to_string(),
            text: text.to_string(),
            kind,
        });
    }
}

fn now_short() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

enum UiEvent {
    Message { from: String, text: String },
    BundleReceived { from: String, payload: Vec<u8> },
    Error(String),
    Disconnected,
}

fn setup_prompt() -> io::Result<(String, String, String)> {
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
    if dest == name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destinataire identique au pseudo",
        ));
    }

    let new_cfg = config::Config {
        relay: Some(addr.clone()),
        pseudo: Some(name.clone()),
    };
    let _ = config::save(&new_cfg);

    println!();
    Ok((addr, name, dest))
}

fn clear_default_pseudo() {
    let cfg = config::load();
    let new_cfg = config::Config {
        relay: cfg.relay,
        pseudo: None,
    };
    let _ = config::save(&new_cfg);
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
    let spk = &keys.signed_pre_key;
    let kpk = &keys.kyber_pre_key;
    PreKeyBundle::new(
        keys.registration_id,
        DeviceId::new(1).unwrap(),
        None,
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

pub fn run() -> io::Result<()> {
    loop {
        let (relay, pseudo, dest) = setup_prompt()?;

        let client = match Client::connect(&relay, &pseudo) {
            Ok(c) => c,
            Err(e) if e.to_string().contains("pseudo deja pris") => {
                clear_default_pseudo();
                eprintln!();
                eprintln!("  Ce pseudo est deja utilise. Choisis-en un autre.");
                eprintln!();
                continue;
            }
            Err(e) if e.to_string().contains("relay injoignable") => {
                eprintln!();
                eprintln!("  {}", e);
                eprintln!("  Verifie l'adresse du relay, ou lance-en un en local :");
                eprintln!("      khimy relay 127.0.0.1:9000");
                eprintln!();
                continue;
            }
            Err(e) => return Err(e),
        };

        match run_with_client(client, relay, pseudo, dest) {
            Ok(()) => return Ok(()),
            Err(e) if e.to_string().contains("n'est pas connecte") => {
                eprintln!();
                eprintln!("  Reessaie quand il sera connecte, ou change de destinataire.");
                eprintln!();
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

fn run_with_client(
    mut client: Client,
    relay: String,
    pseudo: String,
    dest: String,
) -> io::Result<()> {
    let keys = keys::load_or_generate_keys(&pseudo).expect("keys");
    let mut store = make_store(&keys);
    persist::load_all(&store, &pseudo);

    println!("[{}] connecte a {}", pseudo, relay);

    let bundle = build_bundle(&keys);
    let bundle_bytes = serialize_bundle(&bundle)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
    client.publish_bundle(&bundle_bytes)?;
    println!("[{}] bundle publie", pseudo);

    client.request_bundle(&dest)?;
    let dest_bundle = loop {
        match client.recv_timeout(Duration::from_secs(5))? {
            Some((KIND_BUNDLE, from, payload)) => {
                let b = deserialize_bundle(&payload).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e))
                })?;
                println!("[{}] bundle de {} recu", pseudo, from);
                break b;
            }
            Some((KIND_ERROR, _, payload)) => {
                let msg = String::from_utf8_lossy(&payload);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("relay: {}", msg),
                ));
            }
            Some((KIND_CIPHERTEXT, _, _)) => {}
            Some((kind, _, _)) => {
                eprintln!("[{}] kind inattendu: 0x{:02x}", pseudo, kind);
            }
            None => {
                eprintln!();
                eprintln!("[!] {} n'est pas connecte au relay.", dest);
                eprintln!("    Demande-lui de lancer khimy de son cote,");
                eprintln!("    ou verifie le pseudo.");
                eprintln!();
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} n'est pas connecte", dest),
                ));
            }
        }
    };

    let my_address = ProtocolAddress::new(pseudo.clone(), DeviceId::new(1).unwrap());
    let mut dest_address = ProtocolAddress::new(dest.clone(), DeviceId::new(1).unwrap());
    let mut rng = rand::rng();

    futures::executor::block_on(session::establish_session(
        &mut store,
        &my_address,
        &dest_address,
        &dest_bundle,
        &mut rng,
    ))
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;

    println!("[{}] session etablie avec {}", pseudo, dest);
    persist::save_all(&store, &pseudo);

    let store = Arc::new(Mutex::new(store));

    let (tx, rx) = mpsc::channel::<UiEvent>();

    let stream_reader = client.stream.try_clone()?;
    let reader_store = Arc::clone(&store);
    let reader_my = my_address.clone();
    let reader_name = pseudo.clone();
    thread::spawn(move || {
        reader_loop(stream_reader, reader_store, reader_my, reader_name, tx);
    });

    if let Err(e) = client.fetch_pending() {
        eprintln!("[{}] avertissement fetch pending: {}", pseudo, e);
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(pseudo.clone(), relay, dest.clone());

    let res = run_app(
        &mut terminal,
        &mut app,
        &mut client,
        &store,
        &my_address,
        &mut dest_address,
        &rx,
    );

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        eprintln!("erreur TUI: {}", e);
    }

    Ok(())
}

fn reader_loop(
    mut stream: std::net::TcpStream,
    store: Arc<Mutex<InMemoryStores>>,
    my_address: ProtocolAddress,
    my_name: String,
    tx: mpsc::Sender<UiEvent>,
) {
    let mut rng = rand::rng();
    loop {
        match network::recv_frame(&mut stream) {
            Ok(frame) => {
                let (kind, from, payload) = match network::decode_envelope(&frame) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if kind == KIND_CIPHERTEXT {
                    let from_addr = ProtocolAddress::new(from.clone(), DeviceId::new(1).unwrap());
                    let mut s = store.lock().unwrap();
                    match try_decrypt(&mut s, &my_address, &from_addr, &payload, &mut rng) {
                        Ok(text) => {
                            persist::save_all(&s, &my_name);
                            let _ = tx.send(UiEvent::Message { from, text });
                        }
                        Err(e) => {
                            let _ = tx.send(UiEvent::Error(format!(
                                "dechiffrement de {} : {:?}",
                                from, e
                            )));
                        }
                    }
                } else if kind == KIND_BUNDLE {
                    let _ = tx.send(UiEvent::BundleReceived { from, payload });
                } else if kind == KIND_ERROR {
                    let msg = String::from_utf8_lossy(&payload).to_string();
                    let _ = tx.send(UiEvent::Error(format!("relay: {}", msg)));
                    break;
                }
            }
            Err(_) => {
                let _ = tx.send(UiEvent::Disconnected);
                break;
            }
        }
    }
}

fn handle_command(app: &mut App, line: &str) -> bool {
    match line {
        "/quit" | "/q" => {
            app.should_quit = true;
            true
        }
        "/clear" => {
            app.messages.clear();
            true
        }
        "/help" => {
            let text = "/quit   /clear   /help   /status   /to <nom>   /banner";
            app.push(MsgKind::System, "", text);
            true
        }
        "/status" => {
            let text = format!("{} @ {} -> {}", app.pseudo, app.relay, app.dest);
            app.push(MsgKind::System, "", &text);
            true
        }
        "/banner" => {
            let lines: Vec<String> = BANNER.iter().map(|s| s.to_string()).collect();
            for b in lines {
                app.push(MsgKind::Banner, "", &b);
            }
            true
        }
        _ => false,
    }
}

fn run_app(
    terminal: &mut Tui,
    app: &mut App,
    client: &mut Client,
    store: &Arc<Mutex<InMemoryStores>>,
    my_address: &ProtocolAddress,
    dest_address: &mut ProtocolAddress,
    rx: &mpsc::Receiver<UiEvent>,
) -> io::Result<()> {
    let mut rng = rand::rng();

    loop {
        terminal.draw(|f| ui(f, app))?;

        loop {
            match rx.try_recv() {
                Ok(UiEvent::Message { from, text }) => {
                    app.push(MsgKind::Other, &from, &text);
                }
                Ok(UiEvent::BundleReceived { from, payload }) => {
                    if app.pending_switch.as_deref() == Some(from.as_str()) {
                        match deserialize_bundle(&payload) {
                            Ok(bundle) => {
                                let new_addr = ProtocolAddress::new(
                                    from.clone(),
                                    DeviceId::new(1).unwrap(),
                                );
                                let est = {
                                    let mut s = store.lock().unwrap();
                                    futures::executor::block_on(session::establish_session(
                                        &mut s,
                                        my_address,
                                        &new_addr,
                                        &bundle,
                                        &mut rng,
                                    ))
                                };
                                match est {
                                    Ok(()) => {
                                        {
                                            let s = store.lock().unwrap();
                                            persist::save_all(&s, &app.pseudo);
                                        }
                                        app.dest = from.clone();
                                        *dest_address = new_addr;
                                        let msg = format!("session etablie avec {}", from);
                                        app.push(MsgKind::System, "", &msg);
                                    }
                                    Err(e) => {
                                        let msg = format!(
                                            "erreur session avec {} : {:?}",
                                            from, e
                                        );
                                        app.push(MsgKind::System, "", &msg);
                                    }
                                }
                            }
                            Err(e) => {
                                let msg = format!("bundle invalide de {} : {:?}", from, e);
                                app.push(MsgKind::System, "", &msg);
                            }
                        }
                        app.pending_switch = None;
                    }
                }
                Ok(UiEvent::Error(msg)) => {
                    app.push(MsgKind::System, "", &msg);
                }
                Ok(UiEvent::Disconnected) => {
                    app.push(MsgKind::System, "", "deconnecte du relay");
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        KeyCode::Char(c) => app.input.push(c),
                        KeyCode::Backspace => {
                            app.input.pop();
                        }
                        KeyCode::Enter => {
                            let line = app.input.trim().to_string();
                            app.input.clear();
                            if line.is_empty() {
                                continue;
                            }

                            if let Some(rest) = line.strip_prefix("/to ") {
                                let new_dest = rest.trim().to_string();
                                if new_dest.is_empty() {
                                    app.push(MsgKind::System, "", "usage: /to <nom>");
                                    continue;
                                }
                                if new_dest == app.pseudo {
                                    let msg = format!("impossible : tu es deja {}", new_dest);
                                    app.push(MsgKind::System, "", &msg);
                                    continue;
                                }
                                if new_dest == app.dest {
                                    let msg = format!("deja en conversation avec {}", new_dest);
                                    app.push(MsgKind::System, "", &msg);
                                    continue;
                                }
                                if app.pending_switch.is_some() {
                                    app.push(
                                        MsgKind::System,
                                        "",
                                        "changement deja en cours, attends...",
                                    );
                                    continue;
                                }
                                if let Err(e) = client.request_bundle(&new_dest) {
                                    let msg = format!("erreur envoi : {}", e);
                                    app.push(MsgKind::System, "", &msg);
                                    continue;
                                }
                                let msg = format!("changement vers {}...", new_dest);
                                app.push(MsgKind::System, "", &msg);
                                app.pending_switch = Some(new_dest);
                                continue;
                            }

                            if handle_command(app, &line) {
                                continue;
                            }

                            let ct = {
                                let mut s = store.lock().unwrap();
                                futures::executor::block_on(session::encrypt_message(
                                    &mut s,
                                    my_address,
                                    dest_address,
                                    line.as_bytes(),
                                    &mut rng,
                                ))
                            };

                            match ct {
                                Ok(cipher) => {
                                    let bytes = cipher.serialize();
                                    if let Err(e) = client.send_ciphertext(&app.dest, &bytes) {
                                        let msg = format!("erreur envoi : {}", e);
                                        app.push(MsgKind::System, "", &msg);
                                    } else {
                                        let pseudo = app.pseudo.clone();
                                        app.push(MsgKind::Mine, &pseudo, &line);
                                    }
                                }
                                Err(e) => {
                                    let msg = format!("erreur chiffrement : {:?}", e);
                                    app.push(MsgKind::System, "", &msg);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn ui(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let banner_height = BANNER.len() as u16;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_height + 2),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(area);

    let mut banner_lines: Vec<Line> = Vec::new();
    for (i, line) in BANNER.iter().enumerate() {
        let color = match i {
            0 | 1 => PINK_BRIGHT,
            2 | 3 => PINK,
            4 => PINK_DIM,
            _ => PINK_DEEP,
        };
        banner_lines.push(Line::from(Span::styled(
            *line,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )));
    }

    let subtitle = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled("e2ee", Style::default().fg(PINK_DEEP)),
        Span::styled(" . ", Style::default().fg(PINK_DEEP)),
        Span::styled(
            &app.pseudo,
            Style::default().fg(PINK).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" @ ", Style::default().fg(PINK_DEEP)),
        Span::styled(&app.relay, Style::default().fg(MUTED)),
        Span::styled(" -> ", Style::default().fg(PINK_DEEP)),
        Span::styled(&app.dest, Style::default().fg(PINK_DIM)),
    ]);
    banner_lines.push(subtitle);

    f.render_widget(
        Paragraph::new(banner_lines).style(Style::default().bg(BG)),
        chunks[0],
    );

    let sep_width = area.width as usize;
    let sep = Line::from(Span::styled(
        "-".repeat(sep_width),
        Style::default().fg(PINK_DEEP),
    ));
    f.render_widget(Paragraph::new(sep), chunks[1]);

    let visible_height = chunks[2].height as usize;
    let start = app.messages.len().saturating_sub(visible_height);

    let items: Vec<ListItem> = app.messages[start..]
        .iter()
        .map(|m| {
            let line = match m.kind {
                MsgKind::System => Line::from(vec![
                    Span::styled(format!(" {} ", m.time), Style::default().fg(PINK_DEEP)),
                    Span::styled(
                        &m.text,
                        Style::default().fg(MUTED).add_modifier(Modifier::ITALIC),
                    ),
                ]),
                MsgKind::Banner => Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        &m.text,
                        Style::default().fg(PINK_DIM).add_modifier(Modifier::BOLD),
                    ),
                ]),
                MsgKind::Mine => Line::from(vec![
                    Span::styled(format!(" {} ", m.time), Style::default().fg(PINK_DEEP)),
                    Span::styled(
                        format!("{} ", m.from),
                        Style::default().fg(PINK_BRIGHT).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&m.text, Style::default().fg(TEXT)),
                ]),
                MsgKind::Other => Line::from(vec![
                    Span::styled(format!(" {} ", m.time), Style::default().fg(PINK_DEEP)),
                    Span::styled(
                        format!("{} ", m.from),
                        Style::default().fg(PINK).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&m.text, Style::default().fg(TEXT)),
                ]),
            };
            ListItem::new(line)
        })
        .collect();

    f.render_widget(List::new(items).style(Style::default().bg(BG)), chunks[2]);

    let sep2 = Line::from(Span::styled(
        "-".repeat(sep_width),
        Style::default().fg(PINK_DEEP),
    ));
    f.render_widget(Paragraph::new(sep2), chunks[3]);

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(PINK_DIM))
        .style(Style::default().bg(BG));

    let input_line = Line::from(vec![
        Span::styled(" > ", Style::default().fg(PINK).add_modifier(Modifier::BOLD)),
        Span::styled(&app.input, Style::default().fg(TEXT)),
    ]);

    f.render_widget(
        Paragraph::new(input_line).block(input_block).style(Style::default().bg(BG)),
        chunks[4],
    );

    let cursor_x = chunks[4].x + 4 + app.input.chars().count() as u16;
    let cursor_y = chunks[4].y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
}
