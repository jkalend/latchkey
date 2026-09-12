//! TUI (ADR-0007: ratatui + crossterm; TUI_GUIDE.md for behavior).
//!
//! Fuzzy search over the decrypted index, detail view with masked secrets,
//! credential creation, clipboard copy/countdown, idle auto-lock at 10 minutes
//! (`RPASS_TUI_LOCK_MINS`), explicit `L`-lock, and reveal (`r`) with
//! auto-re-mask after 10 seconds of no input.

use std::io::Stdout;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEventKind};
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
use crate::crypto::kdf::SecretVec;
use crate::gen::GenerateSpec;
use crate::ops::{self, Change, EntryPatch, NewEntry};
use crate::vault::shape::{TotpAlgorithm, TotpSubRecord};
use crate::vault::vault_impl::Vault;
use crate::{clip, totp};
use zeroize::Zeroize;

/// Idle auto-lock, minutes (TUI_GUIDE "Security behaviors").
const DEFAULT_LOCK_MINS: u64 = 10;
/// Re-mask a revealed secret after this much input silence.
const RE_MASK_AFTER: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
enum FormField {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Totp,
}

const FORM_FIELDS: [FormField; 6] = [
    FormField::Title,
    FormField::Username,
    FormField::Password,
    FormField::Url,
    FormField::Notes,
    FormField::Totp,
];

impl FormField {
    fn label(self) -> &'static str {
        match self {
            Self::Title => "Title",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::Url => "URL",
            Self::Notes => "Notes",
            Self::Totp => "TOTP base32 or otpauth:// URI",
        }
    }
}

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
struct EntryForm {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    totp: String,
    field: usize,
}

impl EntryForm {
    fn empty() -> Self {
        Self {
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp: String::new(),
            field: 0,
        }
    }

    fn current_field(&self) -> FormField {
        FORM_FIELDS[self.field]
    }

    fn current_value_mut(&mut self) -> &mut String {
        match self.current_field() {
            FormField::Title => &mut self.title,
            FormField::Username => &mut self.username,
            FormField::Password => &mut self.password,
            FormField::Url => &mut self.url,
            FormField::Notes => &mut self.notes,
            FormField::Totp => &mut self.totp,
        }
    }

    fn value(&self, field: FormField) -> &str {
        match field {
            FormField::Title => &self.title,
            FormField::Username => &self.username,
            FormField::Password => &self.password,
            FormField::Url => &self.url,
            FormField::Notes => &self.notes,
            FormField::Totp => &self.totp,
        }
    }

    fn next(&mut self) {
        self.field = (self.field + 1).min(FORM_FIELDS.len() - 1);
    }

    fn previous(&mut self) {
        self.field = self.field.saturating_sub(1);
    }
}

enum Mode {
    Locked,
    List,
    Detail { item_id: u32 },
    Add,
    Edit { item_id: u32 },
    Delete { item_id: u32 },
}

struct App {
    vault_path: std::path::PathBuf,
    vault: Option<Vault>,
    mode: Mode,
    search: String,
    list_state: ListState,
    searching: bool,
    /// item_id of the currently-revealed secret, and when it was revealed.
    revealed: Option<(u32, Instant)>,
    last_input: Instant,
    lock_after: Duration,
    clip_until: Option<Instant>,
    clip_task: Option<JoinHandle<crate::clip::Result<()>>>,
    status: String,
    form: Option<EntryForm>,
    save_failed: bool,
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
            searching: false,
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
            form: None,
            save_failed: false,
        }
    }

    fn lock(&mut self) {
        // Zeroize: drop the vault (SecretVec DEK zeroizes on drop) and every
        // open item with it.
        self.vault = None;
        self.mode = Mode::Locked;
        self.searching = false;
        self.search.clear();
        self.revealed = None;
        self.clip_until = None;
        self.form = None;
        self.save_failed = false;
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
                Event::Key(k) if k.kind != KeyEventKind::Release => {
                    app.last_input = Instant::now();
                    if let Some(code) = handle_key(app, k) {
                        return Ok(code);
                    }
                }
                Event::Key(_) => {}
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
        Mode::List => handle_list_key(app, k),
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
                KeyCode::Char('e') => {
                    start_edit(app, item_id);
                    None
                }
                KeyCode::Char('d') => {
                    app.mode = Mode::Delete { item_id };
                    app.status.clear();
                    None
                }
                _ => None,
            }
        }
        Mode::Add | Mode::Edit { .. } => {
            handle_form_key(app, k);
            None
        }
        Mode::Delete { item_id } => {
            let item_id = *item_id;
            handle_delete_key(app, item_id, k);
            None
        }
    }
}

fn handle_list_key(app: &mut App, k: KeyEvent) -> Option<i32> {
    if app.searching {
        match k.code {
            KeyCode::Esc | KeyCode::Enter => app.searching = false,
            KeyCode::Backspace => {
                app.search.pop();
                app.list_state.select(Some(0));
            }
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                app.search.push(c);
                app.list_state.select(Some(0));
            }
            _ => {}
        }
        return None;
    }

    match k.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(0),
        KeyCode::Char('L') => {
            app.lock();
            None
        }
        KeyCode::Char('/') => {
            app.searching = true;
            None
        }
        KeyCode::Char('a') => {
            app.form = Some(EntryForm::empty());
            app.save_failed = false;
            app.mode = Mode::Add;
            app.status.clear();
            None
        }
        KeyCode::Char('e') => {
            if let Some(entry) = app.selected() {
                start_edit(app, entry.item_id);
            }
            None
        }
        KeyCode::Char('d') => {
            if let Some(entry) = app.selected() {
                app.mode = Mode::Delete {
                    item_id: entry.item_id,
                };
                app.status.clear();
            }
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
            if let Some(entry) = app.selected() {
                app.mode = Mode::Detail {
                    item_id: entry.item_id,
                };
                app.status.clear();
            }
            None
        }
        _ => None,
    }
}

fn handle_form_key(app: &mut App, k: KeyEvent) {
    if app.save_failed {
        if k.code == KeyCode::Esc {
            app.lock();
            app.status = "save failed — vault re-open required".into();
        }
        return;
    }
    match k.code {
        KeyCode::Esc => {
            let (return_mode, status) = match &app.mode {
                Mode::Edit { item_id } => (
                    Mode::Detail { item_id: *item_id },
                    "edit cancelled".to_string(),
                ),
                _ => (Mode::List, "add cancelled".to_string()),
            };
            app.form = None;
            app.mode = return_mode;
            app.status = status;
        }
        KeyCode::Tab | KeyCode::Down => {
            if let Some(form) = app.form.as_mut() {
                form.next();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Some(form) = app.form.as_mut() {
                form.previous();
            }
        }
        KeyCode::Enter => {
            if app
                .form
                .as_ref()
                .is_some_and(|form| form.field == FORM_FIELDS.len() - 1)
            {
                let edit_id = match &app.mode {
                    Mode::Edit { item_id } => Some(*item_id),
                    _ => None,
                };
                if let Some(item_id) = edit_id {
                    submit_edit(app, item_id);
                } else {
                    submit_add(app);
                }
            } else if let Some(form) = app.form.as_mut() {
                form.next();
            }
        }
        KeyCode::Char('g') if k.modifiers.contains(KeyModifiers::CONTROL) => {
            match GenerateSpec::default().generate() {
                Ok(generated) => {
                    if let Some(form) = app.form.as_mut() {
                        form.password = generated.value;
                        app.status = format!(
                            "generated password (~{} bits)",
                            generated.entropy_bits as u64
                        );
                    }
                }
                Err(error) => app.status = format!("generate: {error}"),
            }
        }
        KeyCode::Backspace => {
            if let Some(form) = app.form.as_mut() {
                form.current_value_mut().pop();
            }
        }
        KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(form) = app.form.as_mut() {
                form.current_value_mut().push(c);
            }
        }
        _ => {}
    }
}

fn start_edit(app: &mut App, item_id: u32) {
    let Some(vault) = app.vault.as_mut() else {
        return;
    };
    let Some(entry) = vault
        .entries
        .iter()
        .find(|entry| entry.item_id == item_id && entry.state == crate::vault::shape::LIVE_STATE)
        .cloned()
    else {
        app.status = format!("no such item {item_id}");
        return;
    };
    if let Err(error) = vault.open_item(item_id) {
        app.status = format!("open item: {error}");
        return;
    }
    let Some(record) = vault.open_items.get(&entry.slot) else {
        app.status = "item not open".into();
        return;
    };
    app.form = Some(EntryForm {
        title: entry.title,
        username: entry.username,
        password: String::new(),
        url: record.url.clone(),
        notes: String::new(),
        totp: String::new(),
        field: 0,
    });
    app.mode = Mode::Edit { item_id };
    app.status = "blank secret fields keep existing values; '-' clears".into();
    app.save_failed = false;
}

fn submit_edit(app: &mut App, item_id: u32) {
    let Some(mut form) = app.form.as_ref().cloned() else {
        return;
    };
    if form.title.trim().is_empty() {
        app.status = "title is required".into();
        return;
    }
    let password = match form.password.as_str() {
        "" => Change::Keep,
        "-" => Change::Clear,
        _ => Change::Set(std::mem::take(&mut form.password).into_bytes()),
    };
    let notes = match form.notes.as_str() {
        "" => Change::Keep,
        "-" => Change::Clear,
        _ => Change::Set(std::mem::take(&mut form.notes).into_bytes()),
    };
    let totp = match form.totp.as_str() {
        "" => Change::Keep,
        "-" => Change::Clear,
        _ => match parse_form_totp(&form.totp) {
            Ok(Some(value)) => Change::Set(value),
            Ok(None) => Change::Keep,
            Err(error) => {
                app.status = format!("TOTP: {error}");
                return;
            }
        },
    };
    let patch = EntryPatch {
        title: Some(std::mem::take(&mut form.title)),
        username: Some(std::mem::take(&mut form.username)),
        password,
        url: Some(std::mem::take(&mut form.url)),
        notes,
        totp,
    };
    let Some(vault) = app.vault.as_mut() else {
        return;
    };
    match ops::update_entry(vault, item_id, patch) {
        Ok(changed) => {
            app.form = None;
            app.mode = Mode::Detail { item_id };
            app.status = if changed {
                format!("updated item {item_id}")
            } else {
                "nothing changed".into()
            };
            app.save_failed = false;
        }
        Err(error) => {
            app.save_failed = true;
            app.status = format!("save failed: {error} — Esc to reload");
        }
    }
}

fn handle_delete_key(app: &mut App, item_id: u32, k: KeyEvent) {
    if app.save_failed {
        if k.code == KeyCode::Esc {
            app.lock();
            app.status = "save failed — vault re-open required".into();
        }
        return;
    }
    match k.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let Some(vault) = app.vault.as_mut() else {
                return;
            };
            match ops::delete_entry(vault, item_id) {
                Ok(()) => {
                    app.mode = Mode::List;
                    app.status = format!("deleted item {item_id}");
                    app.list_state.select(Some(0));
                }
                Err(error) => {
                    app.save_failed = true;
                    app.status = format!("save failed: {error} — Esc to reload");
                }
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.mode = Mode::Detail { item_id };
            app.status = "delete cancelled".into();
        }
        _ => {}
    }
}

fn submit_add(app: &mut App) {
    let Some(mut form) = app.form.as_ref().cloned() else {
        return;
    };
    if form.title.trim().is_empty() {
        app.status = "title is required".into();
        return;
    }
    let totp = match parse_form_totp(&form.totp) {
        Ok(value) => value,
        Err(error) => {
            app.status = format!("TOTP: {error}");
            return;
        }
    };
    let password =
        (!form.password.is_empty()).then(|| std::mem::take(&mut form.password).into_bytes());
    let notes = (!form.notes.is_empty()).then(|| std::mem::take(&mut form.notes).into_bytes());
    let input = NewEntry {
        title: std::mem::take(&mut form.title),
        username: std::mem::take(&mut form.username),
        password,
        url: std::mem::take(&mut form.url),
        notes,
        totp,
    };
    let Some(vault) = app.vault.as_mut() else {
        return;
    };
    match ops::add_entry(vault, input) {
        Ok(item_id) => {
            app.form = None;
            app.mode = Mode::Detail { item_id };
            app.status = format!("added item {item_id}");
            app.save_failed = false;
        }
        Err(error) => {
            app.save_failed = true;
            app.status = format!("save failed: {error} — Esc to reload");
        }
    }
}

fn parse_form_totp(input: &str) -> crate::crypto::error::Result<Option<TotpSubRecord>> {
    if input.is_empty() {
        return Ok(None);
    }
    if input.starts_with("otpauth://") {
        let mut params = totp::parse_otpauth_uri(input)?;
        return Ok(Some(TotpSubRecord {
            secret: std::mem::take(&mut params.secret),
            period: params.period,
            digits: params.digits,
            algorithm: params.algorithm,
        }));
    }
    Ok(Some(TotpSubRecord {
        secret: totp::validate_secret(input, TotpAlgorithm::Sha1)?,
        period: 30,
        digits: 6,
        algorithm: TotpAlgorithm::Sha1,
    }))
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
    match std::thread::Builder::new()
        .name("rpass-clipboard".into())
        .spawn(move || clip::copy_and_hold_quiet(&secret, clip::DEFAULT_TIMEOUT_SECS, true))
    {
        Ok(handle) => {
            app.clip_task = Some(handle);
            app.clip_until = Some(Instant::now() + Duration::from_secs(clip::DEFAULT_TIMEOUT_SECS));
            app.status = format!("copied — clears in {}s", clip::DEFAULT_TIMEOUT_SECS);
        }
        Err(error) => app.status = format!("clipboard worker: {error}"),
    }
}

fn copy_password(app: &mut App, item_id: u32) {
    let Some(vault) = app.vault.as_mut() else {
        return;
    };
    let entry = vault
        .entries
        .iter()
        .find(|entry| entry.item_id == item_id && entry.state == crate::vault::shape::LIVE_STATE)
        .cloned();
    let Some(entry) = entry else {
        return;
    };
    if let Err(error) = vault.open_item(item_id) {
        app.status = format!("open item: {error}");
        return;
    }
    let Some(record) = vault.open_items.get(&entry.slot) else {
        return;
    };
    let Some(password) = record.password.clone() else {
        app.status = "item has no password".into();
        return;
    };
    start_clipboard(app, zeroize::Zeroizing::new(password));
}

fn copy_totp(app: &mut App, item_id: u32) {
    let Some(vault) = app.vault.as_mut() else {
        return;
    };
    let entry = vault
        .entries
        .iter()
        .find(|entry| entry.item_id == item_id && entry.state == crate::vault::shape::LIVE_STATE)
        .cloned();
    let Some(entry) = entry else {
        return;
    };
    if let Err(error) = vault.open_item(item_id) {
        app.status = format!("open item: {error}");
        return;
    }
    let Some(record) = vault.open_items.get(&entry.slot) else {
        return;
    };
    let Some(params) = record.totp.as_ref() else {
        app.status = "item has no TOTP secret".into();
        return;
    };
    match totp::totp_now(&totp::TotpParams::from(params)) {
        Ok(now) => start_clipboard(app, zeroize::Zeroizing::new(now.code.into_bytes())),
        Err(error) => app.status = format!("totp: {error}"),
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
        Mode::Add | Mode::Edit { .. } => draw_form(f, app, chunks[1]),
        Mode::Delete { item_id } => draw_delete(f, app, item_id, chunks[1]),
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
        .map(|entry| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<40}", entry.title), Style::default()),
                Span::styled(entry.username.clone(), Style::default().fg(Color::DarkGray)),
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
            Span::styled(
                if app.searching {
                    " search: "
                } else {
                    " / search: "
                },
                Style::default().fg(Color::Cyan),
            ),
            search,
            Span::styled(
                "   a add   e edit   d delete ",
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_detail(f: &mut Frame, app: &mut App, item_id: u32, area: Rect) {
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    let Some(entry) = vault
        .entries
        .iter()
        .find(|entry| entry.item_id == item_id && entry.state == crate::vault::shape::LIVE_STATE)
        .cloned()
    else {
        return;
    };
    if let Some(vault) = app.vault.as_mut() {
        if !vault.open_items.contains_key(&entry.slot) {
            if let Err(error) = vault.open_item(item_id) {
                app.status = format!("could not decrypt item: {error}");
                return;
            }
        }
    }
    let Some(vault) = app.vault.as_ref() else {
        return;
    };
    let Some(record) = vault.open_items.get(&entry.slot) else {
        return;
    };

    let revealed_now = app
        .revealed
        .map(|(revealed_id, _)| revealed_id == item_id)
        .unwrap_or(false);
    let mask = |secret: &str| {
        if revealed_now {
            secret.to_string()
        } else {
            "•".repeat(secret.chars().count().max(8))
        }
    };
    let password = match &record.password {
        Some(password) => format!("password:  {}", mask(&String::from_utf8_lossy(password))),
        None => "password:  (none)".to_string(),
    };
    let totp = if record.totp.is_some() {
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
            if record.url.is_empty() {
                "—"
            } else {
                &record.url
            }
        )),
        Line::from(password),
        Line::from(totp),
        Line::from(""),
        Line::from(Span::styled(
            "c copy   r reveal (10s)   t copy TOTP   e edit   d delete   Esc back",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let Some(form) = app.form.as_ref() else {
        return;
    };
    let editing = matches!(app.mode, Mode::Edit { .. });
    let lines: Vec<Line> = FORM_FIELDS
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let focused = index == form.field;
            let raw = form.value(*field);
            let secret = matches!(
                field,
                FormField::Password | FormField::Notes | FormField::Totp
            );
            let value = if editing && secret && raw == "-" {
                "(clear)".to_string()
            } else if secret && raw.is_empty() {
                if editing {
                    "(unchanged; '-' clears)".to_string()
                } else {
                    "(optional)".to_string()
                }
            } else if secret {
                "•".repeat(raw.chars().count().max(8))
            } else if raw.is_empty() {
                if matches!(field, FormField::Title) {
                    "(required)".to_string()
                } else {
                    "(empty)".to_string()
                }
            } else {
                raw.to_string()
            };
            Line::from(vec![
                Span::styled(
                    format!("{:>30}: ", field.label()),
                    if focused {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                ),
                Span::raw(value),
            ])
        })
        .collect();
    let title = if editing {
        " edit credential "
    } else {
        " add credential "
    };
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_delete(f: &mut Frame, app: &App, item_id: u32, area: Rect) {
    let Some(entry) = app
        .vault
        .as_ref()
        .and_then(|vault| vault.entries.iter().find(|entry| entry.item_id == item_id))
    else {
        return;
    };
    let text = vec![
        Line::from(Span::styled(
            "Delete credential?",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("title:    {}", entry.title)),
        Line::from(format!("username: {}", entry.username)),
        Line::from(format!("item_id:  {}", entry.item_id)),
        Line::from(""),
        Line::from("Press y to delete; n or Esc to cancel."),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let help = if matches!(app.mode, Mode::Add | Mode::Edit { .. }) {
        " Tab fields   Enter next/save   Ctrl-G generate   Esc cancel "
    } else if matches!(app.mode, Mode::Delete { .. }) {
        " y delete   n/Esc cancel "
    } else {
        " L lock   q quit "
    };
    let mut spans = vec![Span::styled(help, Style::default().fg(Color::DarkGray))];
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ciphers::Algorithm;
    use crate::crypto::kdf::KdfParams;

    #[test]
    fn add_form_persists_all_fields() {
        let path = std::env::temp_dir().join(format!("rpass_tui_add_{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let password = SecretVec::new(b"test-password".to_vec().into_boxed_slice());
        let vault = Vault::create(
            &path,
            &password,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        let mut app = App::new(path.clone());
        app.vault = Some(vault);
        app.mode = Mode::Add;
        app.form = Some(EntryForm {
            title: "example.com".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: "note".into(),
            totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            field: FORM_FIELDS.len() - 1,
        });

        submit_add(&mut app);
        assert!(matches!(app.mode, Mode::Detail { .. }));
        assert!(app.form.is_none());
        drop(app);

        let mut reopened = Vault::open(&path, &password).unwrap();
        let entry = reopened.entries[0].clone();
        reopened.open_item(entry.item_id).unwrap();
        let record = &reopened.open_items[&entry.slot];
        assert_eq!(entry.title, "example.com");
        assert_eq!(entry.username, "alice");
        assert_eq!(record.password.as_deref(), Some(b"secret".as_slice()));
        assert_eq!(record.url, "https://example.com");
        assert_eq!(record.notes.as_deref(), Some(b"note".as_slice()));
        assert!(record.totp.is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn edit_form_hides_existing_secrets_and_delete_persists() {
        let path = std::env::temp_dir().join(format!("rpass_tui_edit_{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let password = SecretVec::new(b"test-password".to_vec().into_boxed_slice());
        let mut vault = Vault::create(
            &path,
            &password,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        let item_id = ops::add_entry(
            &mut vault,
            NewEntry {
                title: "old.example".into(),
                username: "alice".into(),
                password: Some(b"old-secret".to_vec()),
                url: "https://old.example".into(),
                notes: Some(b"sensitive note".to_vec()),
                totp: parse_form_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            },
        )
        .unwrap();
        let mut app = App::new(path.clone());
        app.vault = Some(vault);
        app.mode = Mode::Detail { item_id };

        start_edit(&mut app, item_id);
        let form = app.form.as_ref().unwrap();
        assert_eq!(form.title, "old.example");
        assert_eq!(form.url, "https://old.example");
        assert!(form.password.is_empty());
        assert!(form.notes.is_empty());
        assert!(form.totp.is_empty());

        let form = app.form.as_mut().unwrap();
        form.title = "new.example".into();
        form.username = "bob".into();
        form.password = "new-secret".into();
        form.url = "https://new.example".into();
        form.notes = "-".into();
        form.totp = "-".into();
        submit_edit(&mut app, item_id);
        assert!(matches!(app.mode, Mode::Detail { .. }));
        let vault = app.vault.as_ref().unwrap();
        let entry = vault
            .entries
            .iter()
            .find(|entry| entry.item_id == item_id)
            .unwrap();
        let record = &vault.open_items[&entry.slot];
        assert_eq!(entry.title, "new.example");
        assert_eq!(entry.username, "bob");
        assert_eq!(record.password.as_deref(), Some(b"new-secret".as_slice()));
        assert_eq!(record.url, "https://new.example");
        assert!(record.notes.is_none());
        assert!(record.totp.is_none());

        app.mode = Mode::Delete { item_id };
        handle_delete_key(
            &mut app,
            item_id,
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
        );
        drop(app);
        let reopened = Vault::open(&path, &password).unwrap();
        assert_eq!(
            reopened.entries[0].state,
            crate::vault::shape::TOMBSTONE_STATE
        );
        let _ = std::fs::remove_file(path);
    }
}
