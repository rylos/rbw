// `rbw tui`: search the vault as you type, copy with one key.
//
// The list is decrypted once at startup (names, users, folders and uris, no
// secrets); the selected entry is decrypted on demand, except for entries
// with master password reprompt, which wait for an explicit Enter. Copies go
// through the agent, which clears the clipboard after CLIPBOARD_SECONDS.
// The sidebar (views.rs) narrows the list like the official clients do.
// Ctrl with a letter copies (P password, U username, T totp), Alt with the
// same letter types it into the previous window instead (typer.rs) and quits,
// like rofi-rbw. Enter opens a menu with these and the other actions.

use std::io::IsTerminal as _;

use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use ratatui::crossterm::{execute, terminal};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize as _};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph,
    Wrap,
};

use crate::commands::{TuiDetails, TuiEntry, TuiVault};
use crate::views::{Row, View};

const CLIPBOARD_SECONDS: u64 = 30;
const MESSAGE_SECONDS: u64 = 4;

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

// the sidebar gets its own column from this width on, below it covers the
// list while it has the focus
const SIDEBAR_WIDTH: u16 = 120;

const GENERATOR_TYPES: [(rbw::pwgen::Type, &str); 5] = [
    (rbw::pwgen::Type::AllChars, "letters, digits and symbols"),
    (rbw::pwgen::Type::NoSymbols, "letters and digits"),
    (rbw::pwgen::Type::NonConfusables, "no look-alike characters"),
    (rbw::pwgen::Type::Numbers, "digits only"),
    (rbw::pwgen::Type::Diceware, "passphrase"),
];

type Term =
    ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>;

#[derive(PartialEq, Eq)]
enum Focus {
    Sidebar,
    List,
    Details,
}

enum Mode {
    Normal,
    ConfirmTrash(String),
    ConfirmPurge(String),
    Help,
    // the selected row
    Settings(usize),
    New(NewForm),
    // the actions on the selected entry (or field), with the selected row
    Actions(usize),
    // the list of choices for the selected row of the new item popup
    Pick(NewForm, Picker),
    Generator,
}

// what a row of the actions menu does: the same as a key, or copying and
// typing the selected field
#[derive(Clone, Copy)]
enum Act {
    Key(KeyCode, KeyModifiers),
    CopyField,
    TypeField,
}

struct Picker {
    filter: String,
    // position among the filtered choices
    selected: usize,
}

// the choices of a new item before the editor opens
#[derive(Clone, Copy, Default)]
struct NewForm {
    row: usize,
    kind: usize,
    // 0 is the personal vault, then the organizations in TuiVault order
    vault: usize,
    // among the writable collections of the chosen organization
    collection: usize,
    // 0 is no folder
    folder: usize,
}

struct Generator {
    // 0 type, 1 length
    row: usize,
    ty: usize,
    len: usize,
    words: usize,
    value: String,
}

impl Generator {
    fn new() -> Self {
        let mut g = Self {
            row: 0,
            ty: 0,
            len: 20,
            words: 5,
            value: String::new(),
        };
        g.generate();
        g
    }

    fn diceware(&self) -> bool {
        GENERATOR_TYPES[self.ty].0 == rbw::pwgen::Type::Diceware
    }

    fn generate(&mut self) {
        let len = if self.diceware() {
            self.words
        } else {
            self.len
        };
        self.value = rbw::pwgen::pwgen(GENERATOR_TYPES[self.ty].0, len);
    }
}

struct App {
    db: rbw::db::Db,
    entries: Vec<TuiEntry>,
    vault: TuiVault,
    rows: Vec<Row>,
    view: View,
    // the selected row of the sidebar
    sidebar: ListState,
    // read from the server when the trash is opened
    trash: Vec<TuiEntry>,
    generator: Generator,
    usage: rbw::usage::Usage,
    matcher: nucleo_matcher::Matcher,
    query: String,
    filtered: Vec<usize>,
    list: ListState,
    details: std::collections::HashMap<String, TuiDetails>,
    detail_error: Option<String>,
    detail_line: usize,
    focus: Focus,
    reveal: bool,
    mode: Mode,
    message: Option<(String, bool, std::time::Instant)>,
    last_sync: Option<std::time::SystemTime>,
    // the agent locked (timeout, rbw lock elsewhere): decrypted details are
    // dropped and the next key that needs a secret unlocks first
    locked: bool,
    quit: bool,
}

enum Outcome {
    // a command that needs the real terminal (editor, pinentry)
    Suspend(Box<dyn FnOnce() -> anyhow::Result<String>>),
    // (what, value): typed into the previous window, then the tui quits
    Type(String, String),
    Reload,
    None,
}

pub fn run(settings: bool) -> anyhow::Result<()> {
    if !std::io::stdout().is_terminal() {
        return Err(anyhow::anyhow!("rbw tui needs a terminal"));
    }
    crate::commands::tui_ensure_unlocked()?;
    if rbw::config::Config::load().is_ok_and(|c| c.tui_auth) {
        crate::actions::authorize_tui()?;
    }
    let mut app = App::load()?;
    if settings {
        app.mode = Mode::Settings(0);
    }

    let mut term = enter()?;
    let res = app.run(&mut term);
    leave()?;
    res
}

fn enter() -> anyhow::Result<Term> {
    terminal::enable_raw_mode()?;
    execute!(std::io::stdout(), terminal::EnterAlternateScreen)?;
    let term = ratatui::Terminal::new(
        ratatui::backend::CrosstermBackend::new(std::io::stdout()),
    )?;
    Ok(term)
}

fn leave() -> anyhow::Result<()> {
    terminal::disable_raw_mode()?;
    execute!(std::io::stdout(), terminal::LeaveAlternateScreen)?;
    Ok(())
}

fn db_mtime() -> Option<std::time::SystemTime> {
    let config = rbw::config::Config::load().ok()?;
    let email = config.email.as_ref()?;
    std::fs::metadata(rbw::dirs::db_file(&config.server_name(), email))
        .ok()?
        .modified()
        .ok()
}

impl App {
    fn load() -> anyhow::Result<Self> {
        let db = crate::commands::load_db()?;
        let entries = crate::commands::tui_entries(&db)?;
        let vault = crate::commands::tui_vault(&db)?;
        let rows = crate::views::rows(&vault, &entries);
        let mut app = Self {
            db,
            entries,
            vault,
            rows,
            view: View::All,
            sidebar: ListState::default().with_selected(Some(0)),
            trash: vec![],
            generator: Generator::new(),
            usage: rbw::usage::Usage::load(),
            matcher: nucleo_matcher::Matcher::new(
                nucleo_matcher::Config::DEFAULT,
            ),
            query: String::new(),
            filtered: vec![],
            list: ListState::default(),
            details: std::collections::HashMap::new(),
            detail_error: None,
            detail_line: 0,
            focus: Focus::List,
            reveal: false,
            mode: Mode::Normal,
            message: None,
            last_sync: db_mtime(),
            locked: false,
            quit: false,
        };
        app.refilter();
        Ok(app)
    }

    // after a write or a sync: keep the query and, when it still exists,
    // the selected entry
    fn reload(&mut self) -> anyhow::Result<()> {
        let selected = self.selected().map(|e| e.id.clone());
        self.db = crate::commands::load_db()?;
        self.entries = crate::commands::tui_entries(&self.db)?;
        self.vault = crate::commands::tui_vault(&self.db)?;
        self.rows = crate::views::rows(&self.vault, &self.entries);
        // a folder or collection that is gone
        let pos = self.rows.iter().position(
            |row| matches!(row, Row::View { view, .. } if *view == self.view),
        );
        if pos.is_none() {
            self.view = View::All;
        }
        self.sidebar.select(Some(pos.unwrap_or(0)));
        if self.view == View::Trash {
            self.load_trash();
        }
        self.details.clear();
        self.last_sync = db_mtime();
        self.refilter();
        if let Some(id) = selected {
            if let Some(pos) =
                self.filtered.iter().position(|&i| self.pool()[i].id == id)
            {
                self.list.select(Some(pos));
                self.on_select();
            }
        }
        Ok(())
    }

    // what the list shows: the vault, or the trash
    fn pool(&self) -> &[TuiEntry] {
        if self.view == View::Trash {
            &self.trash
        } else {
            &self.entries
        }
    }

    fn selected(&self) -> Option<&TuiEntry> {
        self.list
            .selected()
            .and_then(|i| self.filtered.get(i))
            .map(|&i| &self.pool()[i])
    }

    fn load_trash(&mut self) {
        match crate::items::trashed() {
            Ok(items) => {
                self.trash = items
                    .into_iter()
                    .map(|(id, name, deleted)| TuiEntry {
                        id,
                        name,
                        user: None,
                        folder: None,
                        uris: vec![],
                        kind: "deleted",
                        reprompt: false,
                        attachments: 0,
                        org_id: None,
                        folder_id: None,
                        collection_ids: vec![],
                        favorite: false,
                        archived: false,
                        deleted: Some(deleted),
                    })
                    .collect();
            }
            Err(e) => {
                self.trash.clear();
                self.message(format!("{e:#}"), true);
            }
        }
    }

    fn set_view(&mut self, view: View) {
        if view == self.view {
            return;
        }
        self.view = view;
        if self.view == View::Trash {
            self.load_trash();
        }
        self.refilter();
    }

    // moves the sidebar selection over the views, skipping the headers, and
    // shows the view right away
    fn sidebar_move(&mut self, delta: isize) {
        let selectable: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| matches!(row, Row::View { .. }))
            .map(|(i, _)| i)
            .collect();
        let Some(last) = selectable.len().checked_sub(1) else {
            return;
        };
        let cur = self.sidebar.selected().unwrap_or(0);
        let at = selectable.iter().position(|&i| i >= cur).unwrap_or(0);
        let next = selectable[at.saturating_add_signed(delta).min(last)];
        self.sidebar.select(Some(next));
        if let Some(Row::View { view, .. }) = self.rows.get(next) {
            let view = view.clone();
            self.set_view(view);
        }
    }

    fn haystack(entry: &TuiEntry) -> String {
        let mut s = entry.name.clone();
        for part in entry.user.iter().chain(entry.folder.iter()) {
            s.push(' ');
            s.push_str(part);
        }
        for uri in &entry.uris {
            s.push(' ');
            s.push_str(&host(uri));
        }
        s
    }

    fn refilter(&mut self) {
        let usage = &self.usage;
        // the usage score only breaks ties and nudges, it never hides a
        // better match
        let bonus =
            |e: &TuiEntry| (usage.score(&e.id).ln_1p() * 8.0).min(40.0);
        let pool = if self.view == View::Trash {
            &self.trash
        } else {
            &self.entries
        };
        let view = &self.view;
        let visible = |e: &TuiEntry| *view == View::Trash || view.matches(e);
        let mut scored: Vec<(f64, usize)> = if self.query.trim().is_empty() {
            pool.iter()
                .enumerate()
                .filter(|(_, e)| visible(e))
                .map(|(i, e)| (bonus(e), i))
                .collect()
        } else {
            let pattern = nucleo_matcher::pattern::Pattern::parse(
                &self.query,
                nucleo_matcher::pattern::CaseMatching::Smart,
                nucleo_matcher::pattern::Normalization::Smart,
            );
            let mut buf = vec![];
            pool.iter()
                .enumerate()
                .filter(|(_, e)| visible(e))
                .filter_map(|(i, e)| {
                    let hay = Self::haystack(e);
                    let hay = nucleo_matcher::Utf32Str::new(&hay, &mut buf);
                    pattern
                        .score(hay, &mut self.matcher)
                        .map(|score| (f64::from(score) + bonus(e), i))
                })
                .collect()
        };
        let entries = pool;
        scored.sort_by(|(a, i), (b, j)| {
            b.total_cmp(a).then_with(|| {
                entries[*i]
                    .name
                    .to_lowercase()
                    .cmp(&entries[*j].name.to_lowercase())
            })
        });
        self.filtered = scored.into_iter().map(|(_, i)| i).collect();
        self.list.select((!self.filtered.is_empty()).then_some(0));
        self.on_select();
    }

    fn on_select(&mut self) {
        self.detail_error = None;
        self.detail_line = 0;
        self.reveal = false;
        if self.focus == Focus::Details {
            self.focus = Focus::List;
        }
        if let Some(entry) = self.selected() {
            if !entry.reprompt
                && entry.deleted.is_none()
                && !self.details.contains_key(&entry.id)
            {
                let id = entry.id.clone();
                self.fetch_details(&id);
            }
        }
    }

    fn fetch_details(&mut self, id: &str) {
        if self.locked {
            return;
        }
        match crate::commands::tui_details(&self.db, id) {
            Ok(details) => {
                self.details.insert(id.to_string(), details);
            }
            Err(e) => self.detail_error = Some(format!("{e:#}")),
        }
    }

    fn message(&mut self, text: impl Into<String>, error: bool) {
        self.message = Some((text.into(), error, std::time::Instant::now()));
    }

    fn move_by(&mut self, delta: isize) {
        if self.focus == Focus::Details {
            let n = self.detail_lines().len();
            if n > 0 {
                self.detail_line =
                    self.detail_line.saturating_add_signed(delta).min(n - 1);
            }
            return;
        }
        if self.filtered.is_empty() {
            return;
        }
        let last = self.filtered.len() - 1;
        let cur = self.list.selected().unwrap_or(0);
        let next = cur.saturating_add_signed(delta).min(last);
        if next != cur {
            self.list.select(Some(next));
            self.on_select();
        }
    }

    // the copyable values of the selected entry, in display order
    fn detail_lines(&self) -> Vec<(String, String, bool)> {
        let Some(entry) = self.selected() else {
            return vec![];
        };
        let Some(details) = self.details.get(&entry.id) else {
            return vec![];
        };
        let mut lines: Vec<(String, String, bool)> = details
            .values
            .iter()
            .map(|v| (v.label.clone(), v.value.clone(), v.secret))
            .collect();
        if let Some(totp) = &details.totp {
            if let Ok((code, _)) = crate::commands::tui_totp(totp) {
                lines.insert(
                    lines.len().min(2),
                    ("totp".to_string(), code, false),
                );
            }
        }
        if let Some(notes) = &details.notes {
            lines.push(("notes".to_string(), notes.clone(), true));
        }
        lines
    }

    fn copy(&mut self, what: &str, value: Option<String>) {
        let Some(entry) = self.selected() else {
            return;
        };
        let id = entry.id.clone();
        let name = entry.name.clone();
        match value {
            Some(value) if !value.is_empty() => {
                match crate::actions::clipboard_store_for(
                    &value,
                    CLIPBOARD_SECONDS,
                ) {
                    Ok(()) => {
                        rbw::usage::Usage::record(&id);
                        self.message(
                            format!(
                                "{what} of {name} copied, cleared in \
                                 {CLIPBOARD_SECONDS}s"
                            ),
                            false,
                        );
                    }
                    Err(e) => self.message(format!("{e:#}"), true),
                }
            }
            _ => self.message(format!("{name} has no {what}"), true),
        }
    }

    fn type_value(&mut self, what: &str, value: Option<String>) -> Outcome {
        match value {
            Some(value) if !value.is_empty() => {
                Outcome::Type(what.to_string(), value)
            }
            _ => {
                let name = self.selected().map_or("", |e| e.name.as_str());
                let msg = format!("{name} has no {what}");
                self.message(msg, true);
                Outcome::None
            }
        }
    }

    // the details of the selection, decrypting them first when needed (an
    // entry with reprompt asks for the master password here)
    fn ensure_details(&mut self) -> Option<TuiDetails> {
        let entry = self.selected()?;
        if entry.deleted.is_some() {
            return None;
        }
        let id = entry.id.clone();
        if !self.details.contains_key(&id) {
            self.fetch_details(&id);
        }
        self.details.get(&id).cloned()
    }

    fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Help => return Outcome::None,
            Mode::Settings(row) => return self.settings_key(key, row),
            Mode::New(form) => return self.new_key(key, form),
            Mode::Actions(row) => return self.actions_key(key, row),
            Mode::Generator => return self.generator_key(key),
            Mode::Pick(form, picker) => {
                return self.pick_key(key, form, picker)
            }
            Mode::ConfirmPurge(id) => {
                if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                    return inline(self, move || {
                        crate::items::purge_id(&id)?;
                        Ok("deleted for good".to_string())
                    });
                }
                self.message("not deleted", false);
                return Outcome::None;
            }
            Mode::ConfirmTrash(id) => {
                if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                    return Outcome::Suspend(Box::new(move || {
                        crate::items::remove(
                            crate::commands::parse_needle(&id).unwrap(),
                            None,
                            None,
                            false,
                            false,
                        )?;
                        Ok("moved to the trash".to_string())
                    }));
                }
                self.message("not moved", false);
                return Outcome::None;
            }
            Mode::Normal => {}
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);

        if self.focus == Focus::Sidebar {
            match key.code {
                KeyCode::Up => self.sidebar_move(-1),
                KeyCode::Down => self.sidebar_move(1),
                KeyCode::Char('k') if ctrl => self.sidebar_move(-1),
                KeyCode::Char('j') if ctrl => self.sidebar_move(1),
                KeyCode::PageUp => self.sidebar_move(-10),
                KeyCode::PageDown => self.sidebar_move(10),
                KeyCode::Home => self.sidebar_move(-1000),
                KeyCode::End => self.sidebar_move(1000),
                KeyCode::Enter
                | KeyCode::Right
                | KeyCode::Tab
                | KeyCode::Esc
                | KeyCode::Left
                | KeyCode::BackTab => self.focus = Focus::List,
                _ => {
                    // anything else works as in the list (typing filters)
                    self.focus = Focus::List;
                    return self.handle_key(key);
                }
            }
            return Outcome::None;
        }

        if self.view == View::Trash && self.focus == Focus::List {
            match key.code {
                KeyCode::Enter if alt => {
                    self.message("restore it first (Enter)", true);
                    return Outcome::None;
                }
                KeyCode::Enter => {
                    let Some(entry) = self.selected() else {
                        return Outcome::None;
                    };
                    let id = entry.id.clone();
                    return inline(self, move || {
                        crate::items::restore_id(&id)?;
                        Ok("restored".to_string())
                    });
                }
                KeyCode::Char('d') if ctrl => {
                    if let Some(entry) = self.selected() {
                        self.mode = Mode::ConfirmPurge(entry.id.clone());
                    }
                    return Outcome::None;
                }
                KeyCode::Char('u' | 't' | 'o' | 'e' | 'f' | 'a' | 'r')
                    if ctrl =>
                {
                    self.message("restore it first (Enter)", true);
                    return Outcome::None;
                }
                KeyCode::Tab | KeyCode::Right => return Outcome::None,
                _ => {}
            }
        }

        match key.code {
            KeyCode::Char('p') if alt => {
                if let Some(details) = self.ensure_details() {
                    let what = primary_label(self.selected().map(|e| e.kind));
                    return self.type_value(what, details.primary);
                }
            }
            KeyCode::Char('p') if ctrl => {
                if let Some(details) = self.ensure_details() {
                    let what = primary_label(self.selected().map(|e| e.kind));
                    self.copy(what, details.primary);
                }
            }
            KeyCode::Char('u') if alt => {
                if let Some(details) = self.ensure_details() {
                    return self.type_value("username", details.username);
                }
            }
            KeyCode::Char('t') if alt => {
                if let Some(details) = self.ensure_details() {
                    let code = details
                        .totp
                        .and_then(|t| crate::commands::tui_totp(&t).ok())
                        .map(|(code, _)| code);
                    return self.type_value("totp code", code);
                }
            }
            KeyCode::Char('c' | 'q') if ctrl => self.quit = true,
            KeyCode::Esc => {
                if self.focus == Focus::Details {
                    self.focus = Focus::List;
                } else if self.query.is_empty() {
                    self.quit = true;
                } else {
                    self.query.clear();
                    self.refilter();
                }
            }
            KeyCode::Up => self.move_by(-1),
            KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') if ctrl => self.move_by(-1),
            KeyCode::Char('j') if ctrl => self.move_by(1),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::Home if self.focus == Focus::List => {
                self.list.select((!self.filtered.is_empty()).then_some(0));
                self.on_select();
            }
            KeyCode::End if self.focus == Focus::List => {
                self.list.select(self.filtered.len().checked_sub(1));
                self.on_select();
            }
            KeyCode::Left | KeyCode::BackTab if self.focus == Focus::List => {
                self.focus = Focus::Sidebar;
            }
            KeyCode::Tab | KeyCode::Right if self.focus == Focus::List => {
                if self.ensure_details().is_some() {
                    self.focus = Focus::Details;
                    self.detail_line = 0;
                }
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left
                if self.focus == Focus::Details =>
            {
                self.focus = Focus::List;
            }
            KeyCode::Enter => {
                // the details first: an entry with reprompt asks for the
                // master password here, not in the middle of the menu
                if self.ensure_details().is_some() {
                    self.mode = Mode::Actions(0);
                }
            }
            KeyCode::Char('u') if ctrl => {
                if let Some(details) = self.ensure_details() {
                    self.copy("username", details.username);
                }
            }
            KeyCode::Char('t') if ctrl => {
                if let Some(details) = self.ensure_details() {
                    let code = details
                        .totp
                        .and_then(|t| crate::commands::tui_totp(&t).ok())
                        .map(|(code, _)| code);
                    self.copy("totp code", code);
                }
            }
            KeyCode::Char('o') if ctrl => self.open_uri(),
            KeyCode::Char('r') if ctrl => {
                if self.ensure_details().is_some() {
                    self.reveal = !self.reveal;
                }
            }
            KeyCode::Char('s') if ctrl => {
                return match crate::actions::sync() {
                    Ok(()) => {
                        self.message("synced", false);
                        Outcome::Reload
                    }
                    Err(e) => {
                        self.message(format!("{e:#}"), true);
                        Outcome::None
                    }
                };
            }
            KeyCode::Char('l') if ctrl => match crate::actions::lock(false) {
                Ok(()) => self.quit = true,
                Err(e) => self.message(format!("{e:#}"), true),
            },
            KeyCode::Char('e') if ctrl => {
                if let Some(entry) = self.selected() {
                    let id = entry.id.clone();
                    return Outcome::Suspend(Box::new(move || {
                        crate::items::edit(
                            crate::commands::parse_needle(&id).unwrap(),
                            None,
                            None,
                            false,
                            &crate::items::Changes::default(),
                        )?;
                        Ok("saved".to_string())
                    }));
                }
            }
            KeyCode::Char('n') if ctrl => {
                self.mode = Mode::New(self.new_form());
            }
            KeyCode::Char('g') if ctrl => {
                self.generator.generate();
                self.mode = Mode::Generator;
            }
            KeyCode::Char('f') if ctrl => {
                if let Some(entry) = self.selected() {
                    let (id, favorite) = (entry.id.clone(), !entry.favorite);
                    return inline(self, move || {
                        crate::items::set_favorite(&id, favorite)?;
                        Ok(if favorite {
                            "added to the favorites"
                        } else {
                            "removed from the favorites"
                        }
                        .to_string())
                    });
                }
            }
            KeyCode::Char('a') if ctrl => {
                if let Some(entry) = self.selected() {
                    let (id, archive) = (entry.id.clone(), !entry.archived);
                    return inline(self, move || {
                        crate::items::set_archived(&id, archive)?;
                        Ok(if archive { "archived" } else { "unarchived" }
                            .to_string())
                    });
                }
            }
            KeyCode::Char('d') if ctrl => {
                if let Some(entry) = self.selected() {
                    self.mode = Mode::ConfirmTrash(entry.id.clone());
                }
            }
            KeyCode::F(1) => self.mode = Mode::Help,
            KeyCode::F(2) => self.mode = Mode::Settings(0),
            KeyCode::Char('?') if self.query.is_empty() => {
                self.mode = Mode::Help;
            }
            KeyCode::Char('w') if ctrl => {
                let trimmed = self.query.trim_end();
                let cut = trimmed.rfind(' ').map_or(0, |i| i + 1);
                self.query.truncate(cut);
                self.refilter();
            }
            KeyCode::Backspace if alt => {
                self.query.clear();
                self.refilter();
            }
            KeyCode::Backspace => {
                if self.query.pop().is_some() {
                    self.refilter();
                }
            }
            KeyCode::Char(c) if !ctrl && !alt => {
                self.query.push(c);
                self.refilter();
            }
            _ => {}
        }
        Outcome::None
    }

    fn open_uri(&mut self) {
        let Some(entry) = self.selected() else {
            return;
        };
        let Some(uri) = entry.uris.iter().find(|u| u.contains("://")) else {
            let name = entry.name.clone();
            self.message(format!("{name} has no web address"), true);
            return;
        };
        let uri = uri.clone();
        match open::that_detached(&uri) {
            Ok(()) => self.message(format!("opened {}", host(&uri)), false),
            Err(e) => self.message(format!("couldn't open {uri}: {e}"), true),
        }
    }

    fn run(&mut self, term: &mut Term) -> anyhow::Result<()> {
        while !self.quit {
            term.draw(|f| self.draw(f))?;
            // redraw at least every half second, for the totp countdown and
            // to let messages expire
            if !event::poll(std::time::Duration::from_millis(500))? {
                self.check_lock();
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if needs_secret(&key) && matches!(self.mode, Mode::Normal) {
                self.check_lock();
                if self.locked {
                    leave()?;
                    let res = crate::commands::tui_ensure_unlocked();
                    *term = enter()?;
                    term.clear()?;
                    if let Err(e) = res {
                        self.message(format!("{e:#}"), true);
                        continue;
                    }
                    self.locked = false;
                    self.on_select();
                }
            }
            match self.handle_key(key) {
                Outcome::None => {}
                Outcome::Type(what, value) => {
                    let id = self.selected().map(|e| e.id.clone());
                    match crate::typer::type_into_previous_window(&value) {
                        Ok(()) => {
                            if let Some(id) = id {
                                rbw::usage::Usage::record(&id);
                            }
                            self.quit = true;
                        }
                        Err(e) => {
                            self.message(
                                format!("can't type the {what}: {e:#}"),
                                true,
                            );
                        }
                    }
                }
                Outcome::Reload => {
                    if let Err(e) = self.reload() {
                        self.message(format!("{e:#}"), true);
                    }
                }
                Outcome::Suspend(f) => {
                    leave()?;
                    let res = f();
                    *term = enter()?;
                    term.clear()?;
                    match res {
                        Ok(msg) => {
                            self.message(msg, false);
                            if let Err(e) = self.reload() {
                                self.message(format!("{e:#}"), true);
                            }
                        }
                        Err(e) => self.message(format!("{e:#}"), true),
                    }
                }
            }
        }
        Ok(())
    }

    // the new item starts from the view: its type, vault, collection or
    // folder
    fn new_form(&self) -> NewForm {
        let mut form = NewForm::default();
        match &self.view {
            View::Kind(kind) => {
                form.kind = crate::views::KINDS
                    .iter()
                    .position(|(k, _)| k == kind)
                    .unwrap_or(0);
            }
            View::Org(id) => {
                form.vault = self.org_index(id);
            }
            View::Collection(id) => {
                if let Some(c) =
                    self.vault.collections.iter().find(|c| &c.id == id)
                {
                    form.vault = self.org_index(&c.org_id);
                    form.collection = self
                        .writable_collections(form.vault)
                        .iter()
                        .position(|w| w.id == *id)
                        .unwrap_or(0);
                }
            }
            View::Folder(Some(id)) => {
                form.folder = self
                    .vault
                    .folders
                    .iter()
                    .position(|(f, _)| f == id)
                    .map_or(0, |i| i + 1);
            }
            _ => {}
        }
        form
    }

    fn org_index(&self, org_id: &str) -> usize {
        self.vault
            .organizations
            .iter()
            .position(|(id, _)| id == org_id)
            .map_or(0, |i| i + 1)
    }

    fn writable_collections(
        &self,
        vault: usize,
    ) -> Vec<&crate::commands::TuiCollection> {
        let Some((org, _)) = vault
            .checked_sub(1)
            .and_then(|i| self.vault.organizations.get(i))
        else {
            return vec![];
        };
        self.vault
            .collections
            .iter()
            .filter(|c| &c.org_id == org && !c.read_only)
            .collect()
    }

    // the rows of the new item popup: type, vault (when there are
    // organizations), collection (for an organization), folder
    fn new_rows(&self, form: &NewForm) -> Vec<usize> {
        let mut rows = vec![0];
        if !self.vault.organizations.is_empty() {
            rows.push(1);
            if form.vault > 0 {
                rows.push(2);
            }
        }
        rows.push(3);
        rows
    }

    fn new_key(&mut self, key: KeyEvent, mut form: NewForm) -> Outcome {
        let rows = self.new_rows(&form);
        let at = rows.iter().position(|&r| r == form.row).unwrap_or(0);
        // step is -1 or 1
        let cycle = |value: usize, n: usize, step: isize| {
            if n == 0 {
                0
            } else if step < 0 {
                (value + n - 1) % n
            } else {
                (value + 1) % n
            }
        };
        let step = match key.code {
            KeyCode::Esc => {
                self.message("nothing created", false);
                return Outcome::None;
            }
            KeyCode::Enter => return self.create(form),
            KeyCode::Up | KeyCode::BackTab => {
                form.row = rows[at.saturating_sub(1)];
                0
            }
            KeyCode::Down | KeyCode::Tab => {
                form.row = rows[(at + 1).min(rows.len() - 1)];
                0
            }
            KeyCode::Left => -1,
            KeyCode::Right => 1,
            KeyCode::Char(' ') => {
                let selected = Self::choice(&form);
                self.mode = Mode::Pick(
                    form,
                    Picker {
                        filter: String::new(),
                        selected,
                    },
                );
                return Outcome::None;
            }
            _ => 0,
        };
        if step != 0 {
            match form.row {
                0 => {
                    form.kind =
                        cycle(form.kind, crate::views::KINDS.len(), step);
                }
                1 => {
                    form.vault = cycle(
                        form.vault,
                        self.vault.organizations.len() + 1,
                        step,
                    );
                    form.collection = 0;
                }
                2 => {
                    form.collection = cycle(
                        form.collection,
                        self.writable_collections(form.vault).len(),
                        step,
                    );
                }
                _ => {
                    form.folder = cycle(
                        form.folder,
                        self.vault.folders.len() + 1,
                        step,
                    );
                }
            }
        }
        self.mode = Mode::New(form);
        Outcome::None
    }

    // the choices of a row of the new item popup, in order
    fn choices(&self, form: &NewForm) -> Vec<String> {
        match form.row {
            0 => crate::views::KINDS
                .iter()
                .map(|(_, label)| (*label).to_string())
                .collect(),
            1 => std::iter::once("My vault".to_string())
                .chain(
                    self.vault.organizations.iter().map(|(_, n)| n.clone()),
                )
                .collect(),
            2 => self
                .writable_collections(form.vault)
                .iter()
                .map(|c| c.name.clone())
                .collect(),
            _ => std::iter::once("none".to_string())
                .chain(self.vault.folders.iter().map(|(_, n)| n.clone()))
                .collect(),
        }
    }

    const fn choice(form: &NewForm) -> usize {
        match form.row {
            0 => form.kind,
            1 => form.vault,
            2 => form.collection,
            _ => form.folder,
        }
    }

    fn set_choice(form: &mut NewForm, i: usize) {
        match form.row {
            0 => form.kind = i,
            1 => {
                if form.vault != i {
                    form.collection = 0;
                }
                form.vault = i;
            }
            2 => form.collection = i,
            _ => form.folder = i,
        }
    }

    // (index among all the choices, label) of those matching the filter
    fn picked(
        &self,
        form: &NewForm,
        picker: &Picker,
    ) -> Vec<(usize, String)> {
        let filter = picker.filter.to_lowercase();
        self.choices(form)
            .into_iter()
            .enumerate()
            .filter(|(_, c)| c.to_lowercase().contains(&filter))
            .collect()
    }

    fn pick_key(
        &mut self,
        key: KeyEvent,
        mut form: NewForm,
        mut picker: Picker,
    ) -> Outcome {
        let n = self.picked(&form, &picker).len();
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::New(form);
                return Outcome::None;
            }
            KeyCode::Enter => {
                if let Some((i, _)) =
                    self.picked(&form, &picker).get(picker.selected)
                {
                    Self::set_choice(&mut form, *i);
                }
                self.mode = Mode::New(form);
                return Outcome::None;
            }
            KeyCode::Up => {
                picker.selected = picker.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                picker.selected =
                    (picker.selected + 1).min(n.saturating_sub(1));
            }
            KeyCode::PageUp => {
                picker.selected = picker.selected.saturating_sub(10);
            }
            KeyCode::PageDown => {
                picker.selected =
                    (picker.selected + 10).min(n.saturating_sub(1));
            }
            KeyCode::Backspace => {
                picker.filter.pop();
                picker.selected = 0;
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                picker.filter.push(c);
                picker.selected = 0;
            }
            _ => {}
        }
        self.mode = Mode::Pick(form, picker);
        Outcome::None
    }

    fn create(&mut self, form: NewForm) -> Outcome {
        let kind = crate::items::Kind::ALL[form.kind];
        let org = form
            .vault
            .checked_sub(1)
            .and_then(|i| self.vault.organizations.get(i))
            .map(|(id, _)| id.clone());
        let collections: Vec<String> = self
            .writable_collections(form.vault)
            .get(form.collection)
            .map(|c| c.id.clone())
            .into_iter()
            .collect();
        if org.is_some() && collections.is_empty() {
            self.message(
                "this organization has no collection you can write to",
                true,
            );
            return Outcome::None;
        }
        let folder = form
            .folder
            .checked_sub(1)
            .and_then(|i| self.vault.folders.get(i))
            .map(|(_, name)| name.clone());
        let password = (kind == crate::items::Kind::Login).then(|| {
            self.generator.generate();
            self.generator.value.clone()
        });
        let name = self.query.trim().to_string();
        Outcome::Suspend(Box::new(move || {
            crate::items::add(&crate::items::NewItem {
                name,
                username: None,
                uris: vec![],
                folder,
                kind,
                org,
                collections,
                password,
                changes: crate::items::Changes::default(),
                no_edit: false,
                attach: vec![],
            })?;
            Ok("added".to_string())
        }))
    }

    fn generator_key(&mut self, key: KeyEvent) -> Outcome {
        let g = &mut self.generator;
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Outcome::None,
            KeyCode::Enter | KeyCode::Char('c') => {
                let value = g.value.clone();
                match crate::actions::clipboard_store_for(
                    &value,
                    CLIPBOARD_SECONDS,
                ) {
                    Ok(()) => self.message(
                        format!(
                            "generated password copied, cleared in \
                             {CLIPBOARD_SECONDS}s"
                        ),
                        false,
                    ),
                    Err(e) => self.message(format!("{e:#}"), true),
                }
                return Outcome::None;
            }
            KeyCode::Up | KeyCode::BackTab => g.row = 0,
            KeyCode::Down | KeyCode::Tab => g.row = 1,
            KeyCode::Left | KeyCode::Right => {
                let more = key.code == KeyCode::Right;
                let n = GENERATOR_TYPES.len();
                match (g.row, g.diceware()) {
                    (0, _) => {
                        g.ty = if more {
                            (g.ty + 1) % n
                        } else {
                            (g.ty + n - 1) % n
                        }
                    }
                    (_, true) => {
                        g.words =
                            if more { g.words + 1 } else { g.words - 1 }
                                .clamp(3, 20);
                    }
                    (_, false) => {
                        g.len = if more { g.len + 1 } else { g.len - 1 }
                            .clamp(5, 128);
                    }
                }
            }
            // r, Space and anything else: a new one with the same settings
            _ => {}
        }
        g.generate();
        self.mode = Mode::Generator;
        Outcome::None
    }

    // (label, shortcut, action) of the actions menu
    fn actions(&self) -> Vec<(String, &'static str, Act)> {
        let none = KeyModifiers::NONE;
        let (ctrl, alt) = (KeyModifiers::CONTROL, KeyModifiers::ALT);
        if self.focus == Focus::Details {
            let field = self
                .detail_lines()
                .get(self.detail_line)
                .map_or_else(|| "field".to_string(), |(l, _, _)| l.clone());
            return vec![
                (format!("copy {field}"), "", Act::CopyField),
                (format!("type {field}"), "", Act::TypeField),
            ];
        }
        let main = primary_label(self.selected().map(|e| e.kind));
        let details = self.selected().and_then(|e| self.details.get(&e.id));
        let has_user = details.is_some_and(|d| d.username.is_some());
        let has_totp = details.is_some_and(|d| d.totp.is_some());
        let has_uri = self
            .selected()
            .is_some_and(|e| e.uris.iter().any(|u| u.contains("://")));
        let mut rows = vec![
            (
                format!("copy {main}"),
                "^P",
                Act::Key(KeyCode::Char('p'), ctrl),
            ),
            (
                format!("type {main}"),
                "Alt+P",
                Act::Key(KeyCode::Char('p'), alt),
            ),
        ];
        if has_user {
            rows.push((
                "copy username".to_string(),
                "^U",
                Act::Key(KeyCode::Char('u'), ctrl),
            ));
            rows.push((
                "type username".to_string(),
                "Alt+U",
                Act::Key(KeyCode::Char('u'), alt),
            ));
        }
        if has_totp {
            rows.push((
                "copy totp code".to_string(),
                "^T",
                Act::Key(KeyCode::Char('t'), ctrl),
            ));
            rows.push((
                "type totp code".to_string(),
                "Alt+T",
                Act::Key(KeyCode::Char('t'), alt),
            ));
        }
        if has_uri {
            rows.push((
                "open the web address".to_string(),
                "^O",
                Act::Key(KeyCode::Char('o'), ctrl),
            ));
        }
        rows.push((
            "show the fields".to_string(),
            "Tab",
            Act::Key(KeyCode::Tab, none),
        ));
        rows.push((
            "edit".to_string(),
            "^E",
            Act::Key(KeyCode::Char('e'), ctrl),
        ));
        let favorite = self.selected().is_some_and(|e| e.favorite);
        rows.push((
            if favorite {
                "remove from the favorites"
            } else {
                "add to the favorites"
            }
            .to_string(),
            "^F",
            Act::Key(KeyCode::Char('f'), ctrl),
        ));
        let archived = self.selected().is_some_and(|e| e.archived);
        rows.push((
            if archived { "unarchive" } else { "archive" }.to_string(),
            "^A",
            Act::Key(KeyCode::Char('a'), ctrl),
        ));
        rows.push((
            "move to the trash".to_string(),
            "^D",
            Act::Key(KeyCode::Char('d'), ctrl),
        ));
        rows
    }

    fn run_act(&mut self, act: Act) -> Outcome {
        match act {
            Act::Key(code, modifiers) => {
                self.handle_key(KeyEvent::new(code, modifiers))
            }
            Act::CopyField | Act::TypeField => {
                let lines = self.detail_lines();
                let Some((label, value, _)) =
                    lines.get(self.detail_line).cloned()
                else {
                    return Outcome::None;
                };
                if matches!(act, Act::TypeField) {
                    self.type_value(&label, Some(value))
                } else {
                    self.copy(&label, Some(value));
                    Outcome::None
                }
            }
        }
    }

    fn actions_key(&mut self, key: KeyEvent, row: usize) -> Outcome {
        let rows = self.actions();
        match key.code {
            KeyCode::Esc => Outcome::None,
            KeyCode::Up => {
                self.mode = Mode::Actions(row.saturating_sub(1));
                Outcome::None
            }
            KeyCode::Down => {
                self.mode = Mode::Actions(
                    (row + 1).min(rows.len().saturating_sub(1)),
                );
                Outcome::None
            }
            KeyCode::Enter => rows
                .get(row)
                .map_or(Outcome::None, |(_, _, act)| self.run_act(*act)),
            // a shortcut works here too, and closes the menu
            _ => self.handle_key(key),
        }
    }

    fn settings_key(&mut self, key: KeyEvent, row: usize) -> Outcome {
        let step = match key.code {
            KeyCode::Esc | KeyCode::F(2) | KeyCode::Char('q') => {
                return Outcome::None;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.mode = Mode::Settings(row.saturating_sub(1));
                return Outcome::None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.mode =
                    Mode::Settings((row + 1).min(crate::settings::ROWS - 1));
                return Outcome::None;
            }
            KeyCode::Left | KeyCode::Char('h') => -1,
            KeyCode::Right | KeyCode::Char('l' | ' ') | KeyCode::Enter => 1,
            _ => {
                self.mode = Mode::Settings(row);
                return Outcome::None;
            }
        };
        self.mode = Mode::Settings(row);
        let settings = crate::settings::Settings::load();
        match crate::settings::change(&settings, row, step) {
            crate::settings::Change::Done(Ok(msg)) => {
                self.message(msg, false);
                Outcome::None
            }
            crate::settings::Change::Done(Err(e)) => {
                self.message(format!("{e:#}"), true);
                Outcome::None
            }
            crate::settings::Change::Prompt(f) => Outcome::Suspend(f),
        }
    }

    fn check_lock(&mut self) {
        // status, not unlocked: a locked agent answers that with an error,
        // which it logs
        let locked = crate::actions::status()
            .ok()
            .flatten()
            .is_none_or(|status| status.locked);
        if locked && !self.locked {
            self.details.clear();
            if self.focus == Focus::Details {
                self.focus = Focus::List;
            }
            self.reveal = false;
        }
        self.locked = locked;
    }

    fn draw(&mut self, f: &mut ratatui::Frame) {
        let area = f.area();
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(area);

        self.draw_input(f, rows[0]);

        let mut body = rows[1];
        if area.width >= SIDEBAR_WIDTH {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(28), Constraint::Min(10)])
                .split(body);
            self.draw_sidebar(f, cols[0]);
            body = cols[1];
        }
        let wide = area.width >= 90;
        let panes = Layout::default()
            .direction(if wide {
                Direction::Horizontal
            } else {
                Direction::Vertical
            })
            .constraints(if wide {
                [Constraint::Percentage(45), Constraint::Percentage(55)]
            } else {
                [Constraint::Percentage(55), Constraint::Percentage(45)]
            })
            .split(body);
        if area.width < SIDEBAR_WIDTH && self.focus == Focus::Sidebar {
            self.draw_sidebar(f, panes[0]);
        } else {
            self.draw_list(f, panes[0]);
        }
        self.draw_details(f, panes[1]);
        self.draw_footer(f, rows[2]);

        match &self.mode {
            Mode::Help => draw_help(f, area),
            Mode::Settings(row) => draw_settings(f, area, *row),
            Mode::New(form) => self.draw_new(f, area, form),
            Mode::Actions(row) => self.draw_actions(f, area, *row),
            Mode::Generator => self.draw_generator(f, area),
            Mode::Pick(form, picker) => self.draw_pick(f, area, form, picker),
            Mode::ConfirmPurge(_) => {
                let name = self.selected().map_or("", |e| e.name.as_str());
                draw_popup(
                    f,
                    area,
                    "Delete for good",
                    vec![
                        Line::from(format!(
                            "Delete {name} for good? It can't be restored."
                        )),
                        Line::from(""),
                        Line::from(vec![
                            "y".bold().fg(ACCENT),
                            " yes   any other key: no".into(),
                        ]),
                    ],
                );
            }
            Mode::ConfirmTrash(_) => {
                let name = self.selected().map_or("", |e| e.name.as_str());
                draw_popup(
                    f,
                    area,
                    "Trash",
                    vec![
                        Line::from(format!("Move {name} to the trash?")),
                        Line::from(""),
                        Line::from(vec![
                            "y".bold().fg(ACCENT),
                            " yes   any other key: no".into(),
                        ]),
                    ],
                );
            }
            Mode::Normal => {}
        }
    }

    fn draw_input(&self, f: &mut ratatui::Frame, area: Rect) {
        let count =
            format!(" {}/{} ", self.filtered.len(), self.pool().len());
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(u16::try_from(count.len()).unwrap_or(12)),
            ])
            .split(area);
        let input = Line::from(vec![
            Span::styled("❯ ", Style::new().fg(ACCENT).bold()),
            Span::raw(&self.query),
        ]);
        f.render_widget(Paragraph::new(input), cols[0]);
        f.render_widget(Paragraph::new(count).fg(DIM), cols[1]);
        if self.focus == Focus::List && matches!(self.mode, Mode::Normal) {
            let x = cols[0].x
                + 2
                + u16::try_from(unicode_width(&self.query)).unwrap_or(0);
            f.set_cursor_position((x.min(cols[0].right()), cols[0].y));
        }
    }

    fn draw_list(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let width = usize::from(area.width.saturating_sub(4));
        let pool = self.pool();
        let items: Vec<ListItem> = self
            .filtered
            .iter()
            .map(|&i| {
                let e = &pool[i];
                let mut spans = vec![];
                if e.favorite {
                    spans.push(Span::styled(
                        "★ ",
                        Style::new().fg(Color::Yellow),
                    ));
                }
                spans.push(Span::raw(e.name.clone()));
                if let Some(deleted) = &e.deleted {
                    spans.push(Span::styled(
                        format!("  deleted {}", day(deleted)),
                        Style::new().fg(DIM),
                    ));
                }
                if let Some(user) = &e.user {
                    spans.push(Span::styled(
                        format!("  {user}"),
                        Style::new().fg(DIM),
                    ));
                }
                let used: usize =
                    spans.iter().map(|s| unicode_width(&s.content)).sum();
                if let Some(folder) = &e.folder {
                    let pad = width
                        .saturating_sub(used + unicode_width(folder) + 1);
                    if pad > 0 {
                        spans.push(Span::raw(" ".repeat(pad)));
                        spans.push(Span::styled(
                            folder.clone(),
                            Style::new().fg(Color::Blue),
                        ));
                    }
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        let border = if self.focus == Focus::List {
            ACCENT
        } else {
            DIM
        };
        let title = self.view.label(&self.vault);
        let list = List::new(items)
            .block(pane(border, &title))
            .highlight_style(
                Style::new()
                    .bg(Color::Indexed(236))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▌");
        f.render_stateful_widget(list, area, &mut self.list);
    }

    fn draw_details(&self, f: &mut ratatui::Frame, area: Rect) {
        let border = if self.focus == Focus::Details {
            ACCENT
        } else {
            DIM
        };
        let Some(entry) = self.selected() else {
            f.render_widget(
                Paragraph::new("no matches").fg(DIM).block(pane(border, "")),
                area,
            );
            return;
        };
        let mut lines = vec![];
        if let Some(deleted) = &entry.deleted {
            lines.push(Line::from(Span::styled(
                format!("in the trash since {}", day(deleted)),
                Style::new().fg(DIM),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                "Enter".bold().fg(ACCENT),
                " restores   ".into(),
                "^D".bold().fg(ACCENT),
                " deletes it for good".into(),
            ]));
            f.render_widget(
                Paragraph::new(Text::from(lines))
                    .wrap(Wrap { trim: false })
                    .block(pane(border, &entry.name)),
                area,
            );
            return;
        }
        let mut meta = vec![];
        if entry.favorite {
            meta.push(Span::styled("★ ", Style::new().fg(Color::Yellow)));
        }
        meta.push(Span::styled(entry.kind, Style::new().fg(DIM)));
        if let Some(org) = &entry.org_id {
            let name = View::Org(org.clone()).label(&self.vault);
            meta.push(Span::styled(
                format!(" · {name}"),
                Style::new().fg(Color::Magenta),
            ));
        }
        if let Some(folder) = &entry.folder {
            meta.push(Span::styled(
                format!(" · {folder}"),
                Style::new().fg(Color::Blue),
            ));
        }
        if entry.archived {
            meta.push(Span::styled(" · archived", Style::new().fg(DIM)));
        }
        if entry.attachments > 0 {
            meta.push(Span::styled(
                format!(" · {} attachment(s)", entry.attachments),
                Style::new().fg(DIM),
            ));
        }
        lines.push(Line::from(meta));
        let collections: Vec<String> = entry
            .collection_ids
            .iter()
            .map(|id| View::Collection(id.clone()).label(&self.vault))
            .collect();
        if !collections.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("collections: {}", collections.join(", ")),
                Style::new().fg(DIM),
            )));
        }
        lines.push(Line::from(""));

        if let Some(details) = self.details.get(&entry.id) {
            let values = self.detail_lines();
            let label_w = values
                .iter()
                .map(|(l, _, _)| unicode_width(l))
                .max()
                .unwrap_or(0)
                .min(14);
            for (n, (label, value, secret)) in values.iter().enumerate() {
                let selected =
                    self.focus == Focus::Details && n == self.detail_line;
                let style = if selected {
                    Style::new().bg(Color::Indexed(236)).bold()
                } else {
                    Style::new()
                };
                let shown = if *secret && !self.reveal {
                    "••••••••".to_string()
                } else {
                    value.clone()
                };
                let mut spans = vec![Span::styled(
                    format!("{label:>label_w$}  "),
                    Style::new().fg(DIM),
                )];
                if label == "totp" {
                    let left = details
                        .totp
                        .as_ref()
                        .and_then(|t| crate::commands::tui_totp(t).ok())
                        .map_or(0, |(_, left)| left);
                    spans.push(Span::styled(
                        shown,
                        style.fg(Color::Green).bold(),
                    ));
                    spans.push(Span::styled(
                        format!("  {left}s"),
                        Style::new().fg(DIM),
                    ));
                    lines.push(Line::from(spans));
                } else if label == "notes" {
                    lines.push(Line::from(""));
                    lines.push(Line::from(
                        Span::styled("notes", Style::new().fg(DIM))
                            .style(style),
                    ));
                    // notes often hold keys and recovery codes: hidden
                    // like the other secrets until ^R
                    if self.reveal {
                        for l in value.lines() {
                            lines.push(Line::from(Span::styled(
                                l.to_string(),
                                style,
                            )));
                        }
                    } else {
                        lines.push(Line::from(Span::styled(
                            format!(
                                "•••• {} line(s), ^R shows them",
                                value.lines().count()
                            ),
                            style.fg(DIM),
                        )));
                    }
                } else {
                    let first =
                        shown.lines().next().unwrap_or("").to_string();
                    let more = shown.lines().count() > 1;
                    spans.push(Span::styled(first, style));
                    if more {
                        spans.push(Span::styled(" …", Style::new().fg(DIM)));
                    }
                    lines.push(Line::from(spans));
                }
            }
            if details.history > 0 {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!(
                        "{} old password(s) in the history",
                        details.history
                    ),
                    Style::new().fg(DIM),
                )));
            }
            for name in &details.attachments {
                lines.push(Line::from(Span::styled(
                    format!("📎 {name}"),
                    Style::new().fg(DIM),
                )));
            }
        } else if let Some(err) = &self.detail_error {
            lines.push(Line::from(Span::styled(
                err.clone(),
                Style::new().fg(Color::Red),
            )));
        } else if self.locked {
            lines.push(Line::from(vec![
                "🔒 locked: ".into(),
                "Enter".bold().fg(ACCENT),
                " unlocks".into(),
            ]));
        } else if entry.reprompt {
            lines.push(Line::from(vec![
                "🔒 protected: ".into(),
                "Enter".bold().fg(ACCENT),
                " or ".into(),
                "Tab".bold().fg(ACCENT),
                " asks for the master password".into(),
            ]));
            for uri in &entry.uris {
                lines.push(Line::from(Span::styled(
                    uri.clone(),
                    Style::new().fg(DIM),
                )));
            }
        }

        f.render_widget(
            Paragraph::new(Text::from(lines))
                .wrap(Wrap { trim: false })
                .block(pane(border, &entry.name)),
            area,
        );
    }

    fn draw_footer(&self, f: &mut ratatui::Frame, area: Rect) {
        if let Some((msg, error, at)) = &self.message {
            if at.elapsed().as_secs() < MESSAGE_SECONDS {
                let color = if *error { Color::Red } else { Color::Green };
                f.render_widget(Paragraph::new(msg.clone()).fg(color), area);
                return;
            }
        }
        // Enter copies the selected field, or the main value of the entry
        let field = self.detail_lines().get(self.detail_line).map_or_else(
            || "field".to_string(),
            |(label, _, _)| label.clone(),
        );
        let field_actions = format!("copy or type {field}");
        let copy_main = format!(
            "copy {}",
            primary_label(self.selected().map(|e| e.kind))
        );
        let keys: &[(&str, &str)] = if self.focus == Focus::Sidebar {
            &[("↑↓", "view"), ("↵/→", "list"), ("F1", "help")]
        } else if self.focus == Focus::Details {
            &[
                ("↵", &field_actions),
                ("^R", "reveal"),
                ("⇥/Esc", "back"),
                ("F1", "help"),
            ]
        } else if self.view == View::Trash {
            &[
                ("↵", "restore"),
                ("^D", "delete for good"),
                ("←", "views"),
                ("F1", "help"),
            ]
        } else {
            &[
                ("↵", "actions"),
                ("^P", &copy_main),
                ("^U", "copy user"),
                ("^T", "copy totp"),
                ("Alt+P U T", "type"),
                ("⇥", "fields"),
                ("←", "views"),
                ("^E", "edit"),
                ("^N", "new"),
                ("^D", "trash"),
                ("^G", "generate"),
                ("F1", "help"),
            ]
        };
        let mut spans = vec![];
        for (k, what) in keys {
            spans.push(Span::styled(*k, Style::new().fg(ACCENT).bold()));
            spans.push(Span::styled(
                format!(" {what}  "),
                Style::new().fg(DIM),
            ));
        }
        let synced =
            self.last_sync.and_then(|t| t.elapsed().ok()).map_or_else(
                || "never synced".to_string(),
                |d| format!("synced {}", ago(d)),
            );
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(
                    u16::try_from(synced.len() + 1).unwrap_or(20),
                ),
            ])
            .split(area);
        f.render_widget(Paragraph::new(Line::from(spans)), cols[0]);
        f.render_widget(Paragraph::new(synced).fg(DIM), cols[1]);
    }
}

impl App {
    fn draw_sidebar(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let width = usize::from(area.width.saturating_sub(4));
        let items: Vec<ListItem> = self
            .rows
            .iter()
            .map(|row| match row {
                Row::Header(title) => {
                    ListItem::new(Line::from(Span::styled(
                        (*title).to_string(),
                        Style::new().fg(DIM).bold(),
                    )))
                }
                Row::View { view, label, count } => {
                    let style = if *view == self.view {
                        Style::new().fg(ACCENT).bold()
                    } else {
                        Style::new()
                    };
                    let count =
                        count.map_or_else(String::new, |c| c.to_string());
                    let label = truncate(
                        label,
                        width.saturating_sub(count.len() + 2),
                    );
                    let pad = width.saturating_sub(
                        unicode_width(&label) + count.len() + 1,
                    );
                    ListItem::new(Line::from(vec![
                        Span::styled(format!(" {label}"), style),
                        Span::raw(" ".repeat(pad)),
                        Span::styled(count, Style::new().fg(DIM)),
                    ]))
                }
            })
            .collect();
        let border = if self.focus == Focus::Sidebar {
            ACCENT
        } else {
            DIM
        };
        let list = List::new(items)
            .block(pane(border, "Vault"))
            .highlight_style(if self.focus == Focus::Sidebar {
                Style::new().bg(Color::Indexed(236))
            } else {
                Style::new()
            });
        f.render_stateful_widget(list, area, &mut self.sidebar);
    }

    fn draw_new(&self, f: &mut ratatui::Frame, area: Rect, form: &NewForm) {
        let collections = self.writable_collections(form.vault);
        let vault = if form.vault == 0 {
            "My vault".to_string()
        } else {
            self.vault.organizations[form.vault - 1].1.clone()
        };
        let collection = collections.get(form.collection).map_or_else(
            || "none you can write to".to_string(),
            |c| c.name.clone(),
        );
        let folder = form
            .folder
            .checked_sub(1)
            .and_then(|i| self.vault.folders.get(i))
            .map_or_else(|| "none".to_string(), |(_, name)| name.clone());
        let values = [
            ("Type", crate::views::KINDS[form.kind].1.to_string()),
            ("Vault", vault),
            ("Collection", collection),
            ("Folder", folder),
        ];
        let mut lines = vec![];
        for row in self.new_rows(form) {
            let (label, value) = &values[row];
            let selected = row == form.row;
            let style = if selected {
                Style::new().bg(Color::Indexed(236)).bold()
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    if selected { "▌" } else { " " },
                    Style::new().fg(ACCENT),
                ),
                Span::styled(format!("{label:<12}"), style),
                Span::styled(format!("‹ {value} ›"), style.fg(ACCENT)),
            ]));
        }
        lines.push(Line::from(""));
        let name = self.query.trim();
        lines.push(Line::from(Span::styled(
            if name.is_empty() {
                "the name is asked in the editor".to_string()
            } else {
                format!("name: {name} (from the filter)")
            },
            Style::new().fg(DIM),
        )));
        let hint = match crate::items::Kind::ALL[form.kind] {
            crate::items::Kind::Login => {
                "the editor starts with a generated password (^G settings)"
            }
            crate::items::Kind::SshKey => "a new ed25519 key is generated",
            _ => "the rest is filled in in the editor",
        };
        lines.push(Line::from(Span::styled(hint, Style::new().fg(DIM))));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            "↑↓".bold().fg(ACCENT),
            " choose  ".fg(DIM),
            "←→".bold().fg(ACCENT),
            " change  ".fg(DIM),
            "Space".bold().fg(ACCENT),
            " list  ".fg(DIM),
            "Enter".bold().fg(ACCENT),
            " create  ".fg(DIM),
            "Esc".bold().fg(ACCENT),
            " cancel".fg(DIM),
        ]));
        draw_popup(f, area, "New item", lines);
    }

    fn draw_generator(&self, f: &mut ratatui::Frame, area: Rect) {
        let g = &self.generator;
        let (length, unit) = if g.diceware() {
            (g.words, "words")
        } else {
            (g.len, "characters")
        };
        let lines = vec![
            Line::from(Span::styled(
                g.value.clone(),
                Style::new().fg(Color::Green).bold(),
            )),
            Line::from(""),
            choice_line("Type", GENERATOR_TYPES[g.ty].1, g.row == 0),
            choice_line("Length", &format!("{length} {unit}"), g.row == 1),
            Line::from(""),
            Line::from(vec![
                "↑↓".bold().fg(ACCENT),
                " choose  ".fg(DIM),
                "←→".bold().fg(ACCENT),
                " change  ".fg(DIM),
                "r".bold().fg(ACCENT),
                " again  ".fg(DIM),
                "Enter".bold().fg(ACCENT),
                " copy  ".fg(DIM),
                "Esc".bold().fg(ACCENT),
                " close".fg(DIM),
            ]),
        ];
        draw_popup(f, area, "Password generator", lines);
    }

    fn draw_actions(&self, f: &mut ratatui::Frame, area: Rect, row: usize) {
        let rows = self.actions();
        let width = rows
            .iter()
            .map(|(l, _, _)| l.chars().count())
            .max()
            .unwrap_or(0);
        let mut lines = vec![];
        for (n, (label, key, _)) in rows.iter().enumerate() {
            let selected = n == row;
            let style = if selected {
                Style::new().bg(Color::Indexed(236)).bold()
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    if selected { "▌" } else { " " },
                    Style::new().fg(ACCENT),
                ),
                Span::styled(format!("{label:<width$}  "), style),
                Span::styled((*key).to_string(), style.fg(ACCENT)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            "↑↓".bold().fg(ACCENT),
            " choose  ".fg(DIM),
            "Enter".bold().fg(ACCENT),
            " do it  ".fg(DIM),
            "Esc".bold().fg(ACCENT),
            " close".fg(DIM),
        ]));
        let title = self.selected().map_or("", |e| e.name.as_str());
        draw_popup(f, area, title, lines);
    }

    fn draw_pick(
        &self,
        f: &mut ratatui::Frame,
        area: Rect,
        form: &NewForm,
        picker: &Picker,
    ) {
        let title =
            ["Type", "Vault", "Collection", "Folder"][form.row.min(3)];
        let picked = self.picked(form, picker);
        let current = Self::choice(form);
        // enough rows to fill most of the screen, scrolled to the selection
        let height = usize::from(area.height.saturating_sub(8)).clamp(3, 20);
        let first = picker.selected.saturating_sub(height - 1);
        let mut lines = vec![Line::from(vec![
            Span::styled("❯ ", Style::new().fg(ACCENT).bold()),
            Span::raw(picker.filter.clone()),
            Span::styled(
                format!("  {}/{}", picked.len(), self.choices(form).len()),
                Style::new().fg(DIM),
            ),
        ])];
        for (n, (i, label)) in
            picked.iter().enumerate().skip(first).take(height)
        {
            let selected = n == picker.selected;
            let mut style = if selected {
                Style::new().bg(Color::Indexed(236)).bold()
            } else {
                Style::new()
            };
            if *i == current {
                style = style.fg(ACCENT);
            }
            lines.push(Line::from(vec![
                Span::styled(
                    if selected { "▌" } else { " " },
                    Style::new().fg(ACCENT),
                ),
                Span::styled(label.clone(), style),
            ]));
        }
        if picked.is_empty() {
            lines.push(Line::from(Span::styled(
                " no matches",
                Style::new().fg(DIM),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            "type".bold().fg(ACCENT),
            " filter  ".fg(DIM),
            "↑↓".bold().fg(ACCENT),
            " move  ".fg(DIM),
            "Enter".bold().fg(ACCENT),
            " choose  ".fg(DIM),
            "Esc".bold().fg(ACCENT),
            " back".fg(DIM),
        ]));
        draw_popup(f, area, title, lines);
    }
}

// a "label  ‹ value ›" row of a popup, marked when selected
fn choice_line(label: &str, value: &str, selected: bool) -> Line<'static> {
    let style = if selected {
        Style::new().bg(Color::Indexed(236)).bold()
    } else {
        Style::new()
    };
    Line::from(vec![
        Span::styled(
            if selected { "▌" } else { " " },
            Style::new().fg(ACCENT),
        ),
        Span::styled(format!("{label:<12}"), style),
        Span::styled(format!("‹ {value} ›"), style.fg(ACCENT)),
    ])
}

// runs a quick server request without leaving the tui, then reloads
fn inline(
    app: &mut App,
    f: impl FnOnce() -> anyhow::Result<String>,
) -> Outcome {
    match f() {
        Ok(msg) => {
            app.message(msg, false);
            Outcome::Reload
        }
        Err(e) => {
            app.message(format!("{e:#}"), true);
            Outcome::None
        }
    }
}

fn truncate(s: &str, width: usize) -> String {
    if unicode_width(s) <= width {
        return s.to_string();
    }
    let mut out = String::new();
    for c in s.chars() {
        if unicode_width(&out) + 2 > width {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

// "2026-10-25T21:31:51.123Z" -> "2026-10-25"
fn day(date: &str) -> &str {
    date.get(..10).unwrap_or(date)
}

// what Enter copies from an entry of this kind
fn primary_label(kind: Option<&str>) -> &'static str {
    match kind {
        Some("card") => "number",
        Some("note") => "notes",
        Some("ssh key") => "public key",
        _ => "password",
    }
}

fn needs_secret(key: &KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Enter | KeyCode::Tab | KeyCode::Right => true,
        KeyCode::Char('p' | 'u' | 't') => ctrl || alt,
        KeyCode::Char('r' | 'e' | 'n' | 'd' | 'f' | 'a') => ctrl,
        _ => false,
    }
}

fn pane(border: Color, title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(border))
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
}

fn draw_popup(
    f: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line>,
) {
    let h = u16::try_from(lines.len() + 2).unwrap_or(10);
    let w = area.width.min(72);
    let popup = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h.min(area.height),
    };
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(pane(ACCENT, title)),
        popup,
    );
}

fn draw_settings(f: &mut ratatui::Frame, area: Rect, row: usize) {
    let settings = crate::settings::Settings::load();
    let quick = settings.pin || settings.system_auth;
    let check = |on: bool| if on { "[x]" } else { "[ ]" };
    let rows: [(String, String, bool); crate::settings::ROWS] = [
        (
            "Session timeout".to_string(),
            format!("‹ {} ›", settings.timeout_label()),
            true,
        ),
        (
            "Timeout action".to_string(),
            format!(
                "‹ {} ›",
                if settings.forget { "log out" } else { "lock" }
            ),
            true,
        ),
        (
            format!("{} Unlock with PIN", check(settings.pin)),
            String::new(),
            true,
        ),
        (
            format!(
                "{} Unlock with system authentication",
                check(settings.system_auth)
            ),
            String::new(),
            true,
        ),
        (
            format!(
                "{} Require the master password on restart",
                check(!settings.saved_password)
            ),
            String::new(),
            quick,
        ),
        (
            format!(
                "{} Unlock automatically (saved password)",
                check(settings.auto_unlock)
            ),
            String::new(),
            true,
        ),
        (
            format!(
                "{} Ask system authentication to open the TUI",
                check(settings.tui_auth)
            ),
            String::new(),
            true,
        ),
    ];
    let mut lines = vec![];
    for (n, (label, value, enabled)) in rows.iter().enumerate() {
        let mut style = if n == row {
            Style::new().bg(Color::Indexed(236)).bold()
        } else {
            Style::new()
        };
        if !enabled {
            style = style.fg(DIM);
        }
        let marker = if n == row { "▌" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(marker, Style::new().fg(ACCENT)),
            Span::styled(format!("{label:<22}"), style),
            Span::styled(value.clone(), style.fg(ACCENT)),
        ]));
        if n == 1 {
            lines.push(Line::from(""));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        crate::settings::Settings::describe(row),
        Style::new().fg(DIM),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        "↑↓".bold().fg(ACCENT),
        " choose  ".fg(DIM),
        "←→ Space".bold().fg(ACCENT),
        " change  ".fg(DIM),
        "Esc".bold().fg(ACCENT),
        " close".fg(DIM),
    ]));
    draw_popup(f, area, "Security", lines);
}

fn draw_help(f: &mut ratatui::Frame, area: Rect) {
    let rows = [
        ("type", "filter (fuzzy; 'exact ^prefix suffix$ !not)"),
        ("↑ ↓  ^K ^J", "move (PgUp PgDn Home End)"),
        ("Enter", "actions on the entry (or the field)"),
        ("^P", "copy password (card number, note, public key)"),
        ("Tab →", "pick a field, Enter copies or types it"),
        ("^U  ^T", "copy username, totp code"),
        (
            "Alt+P Alt+U Alt+T",
            "type them into the previous window, and quit",
        ),
        ("^R", "show or hide secrets"),
        ("^O", "open the web address"),
        ("← ⇧Tab", "views: favorites, types, vaults, folders, trash"),
        ("^E  ^D", "edit, move to the trash"),
        ("^N", "new item (type, vault, collection, folder)"),
        ("^F  ^A", "favorite, archive (toggle)"),
        ("^G", "password generator"),
        ("^S", "sync"),
        ("^L", "lock and quit"),
        ("F2", "security settings (timeout, pin, system unlock)"),
        ("^W  Alt-⌫", "delete word, clear filter"),
        ("Esc  ^C", "clear filter / quit"),
    ];
    let mut lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(
                    format!("{k:>17}  "),
                    Style::new().fg(ACCENT).bold(),
                ),
                Span::raw(*v),
            ])
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "copies are cleared after {CLIPBOARD_SECONDS}s · any key closes"
        ),
        Style::new().fg(DIM),
    )));
    draw_popup(f, area, "rbw-enhanced", lines);
}

fn host(uri: &str) -> String {
    url::Url::parse(uri)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h.trim_start_matches("www.").to_string())
        })
        .unwrap_or_else(|| uri.to_string())
}

fn ago(d: std::time::Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => "just now".to_string(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86400 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86400),
    }
}

fn unicode_width(s: &str) -> usize {
    ratatui::text::Span::raw(s).width()
}
