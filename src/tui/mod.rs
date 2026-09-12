//! TUI (ADR-0007: ratatui + crossterm; TUI_GUIDE.md for behavior).
//!
//! Scope for this skeleton: fuzzy search over the decrypted index
//! (secrets untouched until selection), single-item detail view with
//! masked secrets, copy with countdown, idle auto-lock at 10 minutes
//! (RPASS_TUI_LOCK_MINS), explicit `L`-lock, reveal (`r`) with
//! auto-re-mask after 10 s of no input.

use std::io::Stdout;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::cli::passwords;
use crate::cli::resolve;
use crate::crypto::kdf::SecretVec;
use crate::vault::vault_impl::Vault;
use crate::{clip, totp};

/// Idle auto-lock, minutes (TUI_GUIDE "Security behaviors").
const DEFAULT_LOCK_MINS: u64 = 10;
/// Re-mask a revealed secret after this much input silence.
const RE_MASK_AFTER: Duration = Duration::from_secs(10);

enum Mode {
    Locked,
    List,
    Detail { item_id: u32 },
}

struct App {
    vault_path: std::path::PathBuf,
    vault: Option<Vault>,
    mode: Mode,
    search: String,
    list_state: ListState,
    /// item_id of the currently-revealed secret, and when it was revealed.
    revealed: Option<(u32, Instant)>,
    last_input: Instant,
    lock_after: Duration,
    clip_until: Option<Instant>,
    clip_task: Option<JoinHandle<crate::clip::Result<()>>>,
    status: String,
}

impl App {
    fn new(vault_path: std::path::PathBuf) -> Self {
        let lock_mins = std::env::var("RPASS_TUI_LOCK_MINS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_LOCK_MINS);
        App {
            vault_path,
            vault: None,
            mode: Mode::Locked,
            search: String::new(),
            list_state: ListState::default(),
            revealed: None,
            last_input: Instant::now(),
            lock_after: if lock_mins == 0 {
                Duration::MAX // 0 disables
            } else {
                Duration::from_secs(lock_mins * 60)
            },
            clip_until: None,
            clip_task: None,
            status: String::new(),
        }
    }

    fn lock(&mut self) {
        // Zeroize: drop the vault (SecretVec DEK zeroizes on drop) and every
        // open item with it.
        self.vault = None;
        self.mode = Mode::Locked;
        self.search.clear();
        self.revealed = None;
        self.clip_until = None;
        self.status = "locked — enter master password".into();
    }

    fn unlock(&mut self) -> bool {
        let pw = match passwords::prompt_master() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sv: SecretVec = SecretVec::new(pw.to_vec().into_boxed_slice());
        match Vault::open(&self.vault_path, &sv) {
            Ok(v) => {
                self.vault = Some(v);
                self.mode = Mode::List;
                self.status.clear();
                true
            }
            Err(e) => {
                self.status = format!("unlock failed: {e}");
                false
            }
        }
    }

    /// Filtered, ranked list of live entries matching the search box.
    fn filtered(&self) -> Vec<crate::vault::shape::IndexEntry> {
        let Some(v) = &self.vault else {
            return Vec::new();
        };
        let q = self.search.to_lowercase();
        v.entries
            .iter()
            .filter(|e| e.state == crate::vault::shape::LIVE_STATE)
            .filter(|e| {
                q.is_empty()
                    || e.title.to_lowercase().contains(&q)
                    || e.username.to_lowercase().contains(&q)
            })
            .cloned()
            .collect()
    }

    fn selected(&self) -> Option<crate::vault::shape::IndexEntry> {
        let items = self.filtered();
        let idx = self.list_state.selected()?;
        items.get(idx).cloned()
    }
}

type TuiTerminal = ratatui::Terminal<CrosstermBackend<Stdout>>;

struct TerminalSession {
    terminal: TuiTerminal,
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = self.terminal.show_cursor();
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
    }
}

/// Run the TUI. Returns the process exit code.
pub fn run(vault_path: std::path::PathBuf, quiet: bool) -> i32 {
    let mut app = App::new(vault_path);
    // Prompt for the master password BEFORE entering the alternate screen:
    // the hidden-input prompt needs a normal, cooked-mode terminal.
    app.unlock();

    if !quiet && clip::clipboard_history_enabled() == Some(true) {
        eprintln!(
            "warning: Windows Clipboard History is enabled — copied values are captured by Win+V and auto-clear does not remove them"
        );
    }

    let mut session = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("rpass tui: {e}");
            return 1;
        }
    };

    match event_loop(&mut session.terminal, &mut app) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rpass tui: {e}");
            1
        }
    }
}

fn setup_terminal() -> Result<TerminalSession, String> {
    enable_raw_mode().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    if let Err(e) = out.execute(EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(e.to_string());
    }
    match ratatui::Terminal::new(CrosstermBackend::new(out)) {
        Ok(terminal) => Ok(TerminalSession { terminal }),
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = std::io::stdout().execute(LeaveAlternateScreen);
            Err(e.to_string())
        }
    }
}

fn event_loop(terminal: &mut TuiTerminal, app: &mut App) -> Result<i32, String> {
    loop {
        if app
            .clip_task
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            let result = app
                .clip_task
                .take()
                .expect("finished clipboard task")
                .join();
            app.clip_until = None;
            app.status = match result {
                Ok(Ok(())) => "clipboard cleared".into(),
                Ok(Err(e)) => format!("clipboard: {e}"),
                Err(_) => "clipboard worker failed".into(),
            };
        }
        let now = Instant::now();

        // Idle auto-lock (TUI_GUIDE): fire before drawing so the very next
        // frame shows the lock screen.
        if app.vault.is_some() && now.duration_since(app.last_input) > app.lock_after {
            app.lock();
        }

        // Auto re-mask after 10 s without input.
        if let Some((_, at)) = app.revealed {
            if now.duration_since(at) > RE_MASK_AFTER {
                app.revealed = None;
            }
        }

        terminal.draw(|f| draw(f, app)).map_err(|e| e.to_string())?;
        if crossterm::event::poll(Duration::from_millis(250)).map_err(|e| e.to_string())? {
            match crossterm::event::read().map_err(|e| e.to_string())? {
                Event::Key(k) => {
                    app.last_input = Instant::now();
                    if let Some(code) = handle_key(app, k) {
                        return Ok(code);
                    }
                }
                Event::Mouse(m) => {
                    app.last_input = Instant::now();
                    if let MouseEventKind::ScrollUp = m.kind {
                        scroll(app, -1);
                    } else if let MouseEventKind::ScrollDown = m.kind {
                        scroll(app, 1);
                    }
                }
                _ => app.last_input = Instant::now(),
            }
        }
    }
}

fn scroll(app: &mut App, delta: i64) {
    let len = app.filtered().len();
    if len == 0 {
        return;
    }
    let cur = app.list_state.selected().unwrap_or(0) as i64;
    let next = (cur + delta).clamp(0, len as i64 - 1) as usize;
    app.list_state.select(Some(next));
}

/// Returns Some(exit_code) to quit.
fn handle_key(app: &mut App, k: KeyEvent) -> Option<i32> {
    // Ctrl-C always quits (and drops the DEK with it).
    if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
        return Some(0);
    }

    match &app.mode {
        Mode::Locked => match k.code {
            KeyCode::Enter => {
                app.unlock();
                None
            }
            _ => None,
        },
        Mode::List => match k.code {
            KeyCode::Char('q') | KeyCode::Esc => Some(0),
            KeyCode::Char('L') => {
                app.lock();
                None
            }
            KeyCode::Up => {
                scroll(app, -1);
                None
            }
            KeyCode::Down => {
                scroll(app, 1);
                None
            }
            KeyCode::PageUp => {
                scroll(app, -10);
                None
            }
            KeyCode::PageDown => {
                scroll(app, 10);
                None
            }
            KeyCode::Enter => {
                if let Some(e) = app.selected() {
                    app.mode = Mode::Detail { item_id: e.item_id };
                    app.status.clear();
                }
                None
            }
            KeyCode::Backspace => {
                app.search.pop();
                None
            }
            KeyCode::Char(c) => {
                // '/' focuses search, but any typing goes into search anyway
                // (TUI_GUIDE: no secret ever rendered in the search box —
                // it only filters the index).
                app.search.push(c);
                app.list_state.select(Some(0));
                None
            }
            _ => None,
        },
        Mode::Detail { item_id } => {
            let item_id = *item_id;
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Backspace => {
                    app.mode = Mode::List;
                    app.revealed = None;
                    None
                }
                KeyCode::Char('L') => {
                    app.lock();
                    None
                }
                KeyCode::Char('c') => {
                    copy_password(app, item_id);
                    None
                }
                KeyCode::Char('r') => {
                    app.revealed = Some((item_id, Instant::now()));
                    None
                }
                KeyCode::Char('t') => {
                    copy_totp(app, item_id);
                    None
                }
                _ => None,
            }
        }
    }
}
fn start_clipboard(app: &mut App, secret: zeroize::Zeroizing<Vec<u8>>) {
    if let Some(handle) = app.clip_task.take() {
        if !handle.is_finished() {
            app.clip_task = Some(handle);
            app.status = "clipboard operation already in progress".into();
            return;
        }
        let _ = handle.join();
    }
    // quiet: the Clipboard History warning already fired once at startup
    // (CLI_REFERENCE's warning policy) — not on every copy.
    match std::thread::Builder::new()
        .name("rpass-clipboard".into())
        .spawn(move || clip::copy_and_hold_quiet(&secret, clip::DEFAULT_TIMEOUT_SECS, true))
    {
        Ok(handle) => {
            app.clip_task = Some(handle);
            app.clip_until = Some(Instant::now() + Duration::from_secs(clip::DEFAULT_TIMEOUT_SECS));
            app.status = format!("copied — clears in {}s", clip::DEFAULT_TIMEOUT_SECS);
        }
        Err(e) => app.status = format!("clipboard worker: {e}"),
    }
}

fn copy_password(app: &mut App, item_id: u32) {
    let Some(v) = app.vault.as_mut() else { return };
    let entry = v
        .entries
        .iter()
        .find(|e| e.item_id == item_id && e.state == crate::vault::shape::LIVE_STATE)
        .cloned();
    let Some(entry) = entry else { return };
    if let Err(e) = v.open_item(item_id) {
        app.status = format!("open item: {e}");
        return;
    }
    let Some(rec) = v.open_items.get(&entry.slot) else {
        return;
    };
    let Some(pw) = rec.password.clone() else {
        app.status = "item has no password".into();
        return;
    };
    start_clipboard(app, zeroize::Zeroizing::new(pw));
}

fn copy_totp(app: &mut App, item_id: u32) {
    let Some(v) = app.vault.as_mut() else { return };
    let entry = v
        .entries
        .iter()
        .find(|e| e.item_id == item_id && e.state == crate::vault::shape::LIVE_STATE)
        .cloned();
    let Some(entry) = entry else { return };
    if let Err(e) = v.open_item(item_id) {
        app.status = format!("open item: {e}");
        return;
    }
    let Some(rec) = v.open_items.get(&entry.slot) else {
        return;
    };
    let Some(t) = rec.totp.as_ref() else {
        app.status = "item has no TOTP secret".into();
        return;
    };
    match totp::totp_now(&totp::TotpParams::from(t)) {
        Ok(now) => start_clipboard(app, zeroize::Zeroizing::new(now.code.into_bytes())),
        Err(e) => app.status = format!("totp: {e}"),
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ],
    )
    .split(f.area());

    match app.mode {
        Mode::Locked => draw_locked(f, app, chunks[1]),
        Mode::List => draw_list(f, app, chunks[1]),
        Mode::Detail { item_id } => draw_detail(f, app, item_id, chunks[1]),
    }

    draw_status(f, app, chunks[2]);
}

fn draw_locked(f: &mut Frame, app: &App, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "locked",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("press Enter and enter the master password to unlock"),
        Line::from("Ctrl-C to quit"),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" rpass ")),
        area,
    );
    let _ = app;
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items = app.filtered();
    let list_items: Vec<ListItem> = items
        .iter()
        .map(|e| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<40}", e.title), Style::default()),
                Span::styled(e.username.clone(), Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let search = if app.search.is_empty() {
        Span::styled("/", Style::default().fg(Color::DarkGray))
    } else {
        Span::raw(app.search.clone())
    };

    let list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title(vec![
            Span::styled(" /", Style::default().fg(Color::Cyan)),
            search,
        ]))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_detail(f: &mut Frame, app: &mut App, item_id: u32, area: Rect) {
    let Some(v) = app.vault.as_ref() else { return };
    let Some(entry) = v
        .entries
        .iter()
        .find(|e| e.item_id == item_id && e.state == crate::vault::shape::LIVE_STATE)
        .cloned()
    else {
        return;
    };
    if let Some(v) = app.vault.as_mut() {
        if !v.open_items.contains_key(&entry.slot) {
            if let Err(e) = v.open_item(item_id) {
                app.status = format!("could not decrypt item: {e}");
                return;
            }
        }
    }
    let Some(v) = app.vault.as_ref() else { return };
    let Some(rec) = v.open_items.get(&entry.slot) else {
        return;
    };

    let revealed_now = app.revealed.map(|(id, _)| id == item_id).unwrap_or(false);
    let mask = |s: &str| {
        if revealed_now {
            s.to_string()
        } else {
            "•".repeat(s.chars().count().max(8))
        }
    };

    let pw_line = match &rec.password {
        Some(p) => format!("password:  {}", mask(&String::from_utf8_lossy(p))),
        None => "password:  (none)".to_string(),
    };
    let totp_line = if rec.totp.is_some() {
        "totp:      configured (press t to copy current code)".to_string()
    } else {
        "totp:      (none)".to_string()
    };

    let text = vec![
        Line::from(Span::styled(
            entry.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("username:  {}", entry.username)),
        Line::from(format!(
            "url:       {}",
            if rec.url.is_empty() { "—" } else { &rec.url }
        )),
        Line::from(pw_line),
        Line::from(totp_line),
        Line::from(""),
        Line::from(Span::styled(
            "c copy   r reveal (10s)   t copy TOTP   Esc back",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::styled(
        " L lock   q quit ",
        Style::default().fg(Color::DarkGray),
    )];

    if let Some(until) = app.clip_until {
        let left = until.saturating_duration_since(Instant::now()).as_secs();
        spans.push(Span::styled(
            format!("  clipboard clears in {left}s"),
            Style::default().fg(Color::Yellow),
        ));
    }
    if app.revealed.is_some() {
        spans.push(Span::styled(
            "  SECRET ON SCREEN",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    if !app.status.is_empty() {
        spans.push(Span::styled(
            format!("  {}", app.status),
            Style::default().fg(Color::Cyan),
        ));
    }

    f.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::NONE)),
        area,
    );
}

// `resolve` is used by CLI-side title disambiguation; referenced here so the
// module dependency is explicit (the TUI itself resolves by list selection).
#[allow(unused)]
fn _resolve_marker() {
    let _ = resolve::resolve_title as fn(&Vault, &str, Option<u32>) -> _;
}
