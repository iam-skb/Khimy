//! Interface TUI (Ratatui) pour Khimy — banner ASCII + style dark.

use std::io;
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
    widgets::{List, ListItem, Paragraph},
    Terminal,
};

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

const RED: Color = Color::Rgb(200, 30, 30);
const RED_DIM: Color = Color::Rgb(120, 20, 20);
const GREY: Color = Color::Rgb(120, 120, 120);
const DIM: Color = Color::Rgb(60, 60, 60);
const TEXT: Color = Color::Rgb(220, 220, 220);
const DARK: Color = Color::Rgb(20, 20, 20);

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
    messages: Vec<Message>,
    input: String,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            pseudo: "anon".to_string(),
            relay: "78.232.48.151:9000".to_string(),
            messages: vec![
                Message {
                    time: now_short(),
                    from: "".to_string(),
                    text: "e2ee session · x3dh + double ratchet + ml-kem-1024".to_string(),
                    kind: MsgKind::System,
                },
                Message {
                    time: now_short(),
                    from: "".to_string(),
                    text: "/help for commands · ctrl+c to quit".to_string(),
                    kind: MsgKind::System,
                },
            ],
            input: String::new(),
            should_quit: false,
        }
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

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        eprintln!("erreur TUI: {}", e);
    }

    Ok(())
}

fn run_app(terminal: &mut Tui) -> io::Result<()> {
    let mut app = App::new();

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(Duration::from_millis(100))? {
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
                            match line.as_str() {
                                "/quit" | "/q" => app.should_quit = true,
                                "/clear" => app.messages.clear(),
                                "/help" => app.messages.push(Message {
                                    time: now_short(),
                                    from: "".to_string(),
                                    text: "/quit  /clear  /help  /status  /banner".to_string(),
                                    kind: MsgKind::System,
                                }),
                                "/status" => app.messages.push(Message {
                                    time: now_short(),
                                    from: "".to_string(),
                                    text: format!("{} @ {}", app.pseudo, app.relay),
                                    kind: MsgKind::System,
                                }),
                                "/banner" => {
                                    for b in BANNER {
                                        app.messages.push(Message {
                                            time: now_short(),
                                            from: "".to_string(),
                                            text: b.to_string(),
                                            kind: MsgKind::Banner,
                                        });
                                    }
                                }
                                _ => app.messages.push(Message {
                                    time: now_short(),
                                    from: app.pseudo.clone(),
                                    text: line,
                                    kind: MsgKind::Mine,
                                }),
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

    f.render_widget(
        ratatui::widgets::Block::default().style(Style::default().bg(DARK)),
        area,
    );

    let banner_height = BANNER.len() as u16;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_height + 1),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    // ─── Banner ───────────────────────────────────────────
    let mut banner_lines: Vec<Line> = Vec::new();

    for (i, line) in BANNER.iter().enumerate() {
        let color = if i < 2 {
            RED
        } else if i < 4 {
            Color::Rgb(160, 25, 25)
        } else {
            RED_DIM
        };
        banner_lines.push(Line::from(Span::styled(
            *line,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )));
    }

    let subtitle = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled("e2ee", Style::default().fg(GREY)),
        Span::styled(" · ", Style::default().fg(DIM)),
        Span::styled(
            &app.pseudo,
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" @ ", Style::default().fg(DIM)),
        Span::styled(&app.relay, Style::default().fg(GREY)),
    ]);
    banner_lines.push(subtitle);

    f.render_widget(
        Paragraph::new(banner_lines).style(Style::default().bg(DARK)),
        chunks[0],
    );

    // ─── Separator ────────────────────────────────────────
    let sep_width = area.width as usize;
    let sep = Line::from(Span::styled(
        "·".repeat(sep_width),
        Style::default().fg(DIM),
    ));
    f.render_widget(Paragraph::new(sep), chunks[1]);

    // ─── Messages ─────────────────────────────────────────
    let visible_height = chunks[2].height as usize;
    let start = app.messages.len().saturating_sub(visible_height);

    let items: Vec<ListItem> = app.messages[start..]
        .iter()
        .map(|m| {
            let line = match m.kind {
                MsgKind::System => Line::from(vec![
                    Span::styled(format!(" {} ", m.time), Style::default().fg(DIM)),
                    Span::styled(&m.text, Style::default().fg(GREY)),
                ]),
                MsgKind::Banner => Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        &m.text,
                        Style::default().fg(RED_DIM).add_modifier(Modifier::BOLD),
                    ),
                ]),
                MsgKind::Mine => Line::from(vec![
                    Span::styled(format!(" {} ", m.time), Style::default().fg(DIM)),
                    Span::styled(
                        format!("{} ", m.from),
                        Style::default().fg(RED).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&m.text, Style::default().fg(TEXT)),
                ]),
                MsgKind::Other => Line::from(vec![
                    Span::styled(format!(" {} ", m.time), Style::default().fg(DIM)),
                    Span::styled(
                        format!("{} ", m.from),
                        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&m.text, Style::default().fg(TEXT)),
                ]),
            };
            ListItem::new(line)
        })
        .collect();

    f.render_widget(
        List::new(items).style(Style::default().bg(DARK)),
        chunks[2],
    );

    // ─── Separator ────────────────────────────────────────
    let sep2 = Line::from(Span::styled(
        "·".repeat(sep_width),
        Style::default().fg(DIM),
    ));
    f.render_widget(Paragraph::new(sep2), chunks[3]);

    // ─── Input ────────────────────────────────────────────
    let input_line = Line::from(vec![
        Span::styled(
            "> ",
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(&app.input, Style::default().fg(TEXT)),
    ]);
    f.render_widget(
        Paragraph::new(input_line).style(Style::default().bg(DARK)),
        chunks[4],
    );

    let cursor_x = 2 + app.input.chars().count() as u16;
    let cursor_y = chunks[4].y;
    f.set_cursor_position((cursor_x, cursor_y));
}
