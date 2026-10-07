//! Notifications : bip terminal + notification native macOS.

use std::io::Write;
use std::process::Command;

/// Notification principale : bip + notification systeme.
pub fn message(from: &str, text: &str) {
    beep();
    system_notify(&format!("Message de {}", from), text);
}

/// Bip terminal (ASCII BEL).
fn beep() {
    print!("\x07");
    let _ = std::io::stdout().flush();
}

/// Notification native selon l'OS.
#[cfg(target_os = "macos")]
fn system_notify(title: &str, body: &str) {
    // Trim et escape les guillemets pour l'AppleScript.
    let title_esc = title.replace('"', "'");
    let body_esc = body.replace('"', "'");
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        body_esc, title_esc
    );
    let _ = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .spawn();
}

#[cfg(target_os = "linux")]
fn system_notify(title: &str, body: &str) {
    let _ = Command::new("notify-send")
        .arg(title)
        .arg(body)
        .spawn();
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn system_notify(_title: &str, _body: &str) {
    // Sur les autres OS (Windows, BSD), pas de notification native.
    // Le bip fonctionne quand meme.
}
