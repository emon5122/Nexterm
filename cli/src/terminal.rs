use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal;
use futures_util::{SinkExt, StreamExt};
use std::io::{self, Write};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

type WsWrite = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;
type WsRead = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>;

/// Runs a single command over the terminal WebSocket and returns its exit code.
///
/// This is the fallback used when the server has no REST `/exec` endpoint. It drives the
/// remote PTY shell directly: it brackets the command with unique sentinel markers, then
/// scrapes the output stream between them. Merged stdout/stderr is printed to our stdout
/// (a PTY can't separate the two), and the exit code is parsed from the trailing marker.
pub async fn run_command(ws_url: &str, command: &str) -> Result<i32> {
    use tokio::time::{timeout, Duration, Instant};

    let (ws, _) = connect_async(ws_url).await.context("WebSocket connect failed")?;
    let (mut tx, mut rx) = ws.split();
    // Wide terminal to minimise line wrapping in scraped output.
    tx.send(Message::Text("\x01300,50".into())).await?;

    let tok = format!("{:x}", std::process::id());
    let start = format!("__NT_START_{tok}__");
    let exit_prefix = format!("__NT_EXIT_{tok}__");
    // The leading newline in each printf guarantees the markers land on their own line,
    // even when the command's output has no trailing newline. `$?` is captured before the
    // final printf so the exit code reflects the user's command, not the printf.
    let script = format!(
        "printf '\\n%s\\n' '{start}'; ( {command} ); __ntc=$?; printf '\\n%s%d\\n' '{exit_prefix}' \"$__ntc\"\n"
    );

    // Wait for the shell to actually be ready before sending input. A cold connection (e.g. the
    // session created right after a previous one was torn down) can take seconds to attach the
    // PTY; sending too early loses the input. We wait for the connection's first output, then for
    // the MOTD/prompt to go idle. Disabling echo on its own line keeps the marker scaffolding out
    // of the live session; we drain its resulting prompt before sending the actual command.
    wait_until_idle(&mut rx, Duration::from_secs(30), Duration::from_millis(500)).await?;
    tx.send(Message::Text("stty -echo 2>/dev/null\n".into())).await?;
    wait_until_idle(&mut rx, Duration::from_secs(5), Duration::from_millis(300)).await?;
    tx.send(Message::Text(script)).await?;

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut buf = String::new();
    let mut capturing = false;
    let mut out = String::new();
    let mut exit_code: Option<i32> = None;

    'outer: loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("Command timed out after 120s (no completion marker received)");
        }
        let msg = match timeout(remaining, rx.next()).await {
            Err(_) => anyhow::bail!("Command timed out after 120s"),
            Ok(m) => m,
        };
        match msg {
            Some(Ok(Message::Text(t))) if t.starts_with('\x02') => {
                anyhow::bail!("Server requested interactive 2FA, which non-interactive exec cannot satisfy");
            }
            Some(Ok(Message::Text(t))) => buf.push_str(&t),
            Some(Ok(Message::Binary(d))) => buf.push_str(&String::from_utf8_lossy(&d)),
            Some(Ok(Message::Close(_))) | None => break,
            Some(Err(e)) => return Err(e.into()),
            _ => {}
        }
        while let Some(pos) = buf.find('\n') {
            let raw: String = buf.drain(..=pos).collect();
            let line = strip_ansi(&raw);
            let line = line.trim_end_matches(['\r', '\n']);
            if !capturing {
                if line == start { capturing = true; }
            } else if let Some(rest) = line.strip_prefix(&exit_prefix) {
                exit_code = Some(rest.trim().parse().unwrap_or(-1));
                break 'outer;
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
    }

    // Cancel the single newline the exit-marker printf injected before its output.
    if out.ends_with('\n') { out.pop(); }
    print!("{out}");
    use std::io::Write;
    io::stdout().flush().ok();
    Ok(exit_code.unwrap_or(1))
}

/// Drains incoming terminal output until the shell goes quiet, signalling it is ready for input.
/// Waits up to `first` for the connection's initial output, then returns once no data has
/// arrived for `idle`. Bails on a 2FA prompt or a closed session.
async fn wait_until_idle(rx: &mut WsRead, first: tokio::time::Duration, idle: tokio::time::Duration) -> Result<()> {
    use tokio::time::timeout;
    let mut wait = first;
    loop {
        match timeout(wait, rx.next()).await {
            Err(_) => return Ok(()), // quiet long enough — shell is ready
            Ok(None) | Ok(Some(Ok(Message::Close(_)))) => anyhow::bail!("Session closed before it was ready"),
            Ok(Some(Ok(Message::Text(t)))) if t.starts_with('\x02') => {
                anyhow::bail!("Server requested interactive 2FA, which non-interactive exec cannot satisfy");
            }
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(Some(Ok(_))) => { wait = idle; } // got output; keep draining with the shorter idle window
        }
    }
}

/// Removes ANSI escape sequences (CSI, OSC, and 2-byte escapes) and bell characters
/// so scraped terminal output is plain text.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if ('@'..='~').contains(&n) { break; }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        if n == '\x07' { chars.next(); break; }
                        if n == '\x1b' { chars.next(); if chars.peek() == Some(&'\\') { chars.next(); } break; }
                        chars.next();
                    }
                }
                Some(_) => { chars.next(); }
                None => {}
            },
            '\x07' => {}
            other => out.push(other),
        }
    }
    out
}

pub async fn run_session(ws_url: &str) -> Result<()> {
    let (ws, _) = connect_async(ws_url).await.context("WebSocket connect failed")?;
    let (mut tx, mut rx) = ws.split();
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    tx.send(Message::Text(format!("\x01{cols},{rows}"))).await?;
    terminal::enable_raw_mode()?;
    let result = session_loop(&mut tx, &mut rx).await;
    terminal::disable_raw_mode()?;
    println!();
    result
}

async fn session_loop(tx: &mut WsWrite, rx: &mut WsRead) -> Result<()> {
    let mut stdout = io::stdout();
    let (mut totp_mode, mut totp_buf) = (false, String::new());
    let (mut last_cols, mut last_rows) = terminal::size().unwrap_or((80, 24));
    let mut size_check = tokio::time::interval(std::time::Duration::from_millis(300));

    loop {
        tokio::select! {
            _ = size_check.tick() => {
                if let Ok((c, r)) = terminal::size() {
                    if c != last_cols || r != last_rows {
                        last_cols = c; last_rows = r;
                        tx.send(Message::Text(format!("\x01{c},{r}"))).await?;
                    }
                }
            }
            msg = rx.next() => match msg {
                Some(Ok(Message::Text(text))) if text.starts_with('\x02') => {
                    totp_mode = true;
                    totp_buf.clear();
                    write!(stdout, "\r\n{}", &text[1..])?;
                    stdout.flush()?;
                }
                Some(Ok(Message::Text(text))) => { write!(stdout, "{text}")?; stdout.flush()?; }
                Some(Ok(Message::Binary(data))) => { stdout.write_all(&data)?; stdout.flush()?; }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(e)) => return Err(e.into()),
                _ => {}
            },
            _ = tokio::task::spawn_blocking(|| event::poll(std::time::Duration::from_millis(50))) => {
                while event::poll(std::time::Duration::ZERO)? {
                    match event::read()? {
                        Event::Key(ke) if totp_mode => match ke.code {
                            KeyCode::Enter => {
                                tx.send(Message::Text(format!("\x03{}", totp_buf))).await?;
                                totp_mode = false; totp_buf.clear();
                                write!(stdout, "\r\n")?; stdout.flush()?;
                            }
                            KeyCode::Char(c) => { totp_buf.push(c); write!(stdout, "*")?; stdout.flush()?; }
                            KeyCode::Backspace if totp_buf.pop().is_some() => {
                                write!(stdout, "\x08 \x08")?; stdout.flush()?;
                            }
                            _ => {}
                        },
                        Event::Key(ke) => {
                            let data = key_to_seq(&ke);
                            if !data.is_empty() { tx.send(Message::Text(data)).await?; }
                        }
                        Event::Resize(c, r) => { tx.send(Message::Text(format!("\x01{c},{r}"))).await?; }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

fn key_to_seq(e: &crossterm::event::KeyEvent) -> String {
    let ctrl = e.modifiers.contains(KeyModifiers::CONTROL);
    match e.code {
        KeyCode::Char(c) if ctrl => String::from(((c as u8).wrapping_sub(b'a').wrapping_add(1)) as char),
        KeyCode::Char(c) => String::from(c),
        KeyCode::Enter => "\r".into(),
        KeyCode::Backspace => "\x7f".into(),
        KeyCode::Tab => "\t".into(),
        KeyCode::Esc => "\x1b".into(),
        KeyCode::Up => "\x1b[A".into(),
        KeyCode::Down => "\x1b[B".into(),
        KeyCode::Right => "\x1b[C".into(),
        KeyCode::Left => "\x1b[D".into(),
        KeyCode::Home => "\x1b[H".into(),
        KeyCode::End => "\x1b[F".into(),
        KeyCode::PageUp => "\x1b[5~".into(),
        KeyCode::PageDown => "\x1b[6~".into(),
        KeyCode::Delete => "\x1b[3~".into(),
        KeyCode::Insert => "\x1b[2~".into(),
        KeyCode::F(n @ 1..=4) => format!("\x1b{}", ['O', 'P', 'Q', 'R', 'S'][n as usize]),
        KeyCode::F(n @ 5..=12) => {
            const CODES: [&str; 8] = ["15", "17", "18", "19", "20", "21", "23", "24"];
            format!("\x1b[{}~", CODES[(n - 5) as usize])
        }
        _ => String::new(),
    }
}
