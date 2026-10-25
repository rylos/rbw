// `rbw tui`: search the vault as you type, copy with one key.
//
// The list is decrypted once at startup (names, users, folders and uris, no
// secrets); the selected entry is decrypted on demand, except for entries
// with master password reprompt, which wait for an explicit Enter. Copies go
// through the agent, which clears the clipboard after CLIPBOARD_SECONDS.

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

use crate::commands::{TuiDetails, TuiEntry};

const CLIPBOARD_SECONDS: u64 = 30;
const MESSAGE_SECONDS: u64 = 4;

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

type Term =
    ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>;

#[derive(PartialEq, Eq)]
enum Focus {
    List,
    Details,
}

enum Mode {
    Normal,
    ConfirmTrash(String),
    Help,
    // the selected row
    Settings(usize),
}

struct App {
    db: rbw::db::Db,
    entries: Vec<TuiEntry>,
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
        let mut app = Self {
            db,
            entries,
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
        self.details.clear();
        self.last_sync = db_mtime();
        self.refilter();
        if let Some(id) = selected {
            if let Some(pos) =
                self.filtered.iter().position(|&i| self.entries[i].id == id)
            {
                self.list.select(Some(pos));
            }
        }
        Ok(())
    }

    fn selected(&self) -> Option<&TuiEntry> {
        self.list
            .selected()
            .and_then(|i| self.filtered.get(i))
            .map(|&i| &self.entries[i])
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
        let mut scored: Vec<(f64, usize)> = if self.query.trim().is_empty() {
            (0..self.entries.len())
                .map(|i| (bonus(&self.entries[i]), i))
                .collect()
        } else {
            let pattern = nucleo_matcher::pattern::Pattern::parse(
                &self.query,
                nucleo_matcher::pattern::CaseMatching::Smart,
                nucleo_matcher::pattern::Normalization::Smart,
            );
            let mut buf = vec![];
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    let hay = Self::haystack(e);
                    let hay = nucleo_matcher::Utf32Str::new(&hay, &mut buf);
                    pattern
                        .score(hay, &mut self.matcher)
                        .map(|score| (f64::from(score) + bonus(e), i))
                })
                .collect()
        };
        let entries = &self.entries;
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
        self.focus = Focus::List;
        if let Some(entry) = self.selected() {
            if !entry.reprompt && !self.details.contains_key(&entry.id) {
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

    // the details of the selection, decrypting them first when needed (an
    // entry with reprompt asks for the master password here)
    fn ensure_details(&mut self) -> Option<TuiDetails> {
        let id = self.selected()?.id.clone();
        if !self.details.contains_key(&id) {
            self.fetch_details(&id);
        }
        self.details.get(&id).cloned()
    }

    fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Help => return Outcome::None,
            Mode::Settings(row) => return self.settings_key(key, row),
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
        match key.code {
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
            KeyCode::Char('p' | 'k') if ctrl => self.move_by(-1),
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
                if self.focus == Focus::Details {
                    let lines = self.detail_lines();
                    if let Some((label, value, _)) =
                        lines.get(self.detail_line).cloned()
                    {
                        self.copy(&label, Some(value));
                    }
                } else if let Some(details) = self.ensure_details() {
                    let what = match self.selected().map(|e| e.kind) {
                        Some("card") => "number",
                        Some("note") => "notes",
                        Some("ssh key") => "public key",
                        _ => "password",
                    };
                    self.copy(what, details.primary);
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
                let name = self.query.trim().to_string();
                return Outcome::Suspend(Box::new(move || {
                    crate::items::add(&crate::items::NewItem {
                        name,
                        username: None,
                        uris: vec![],
                        folder: None,
                        secure_note: false,
                        changes: crate::items::Changes::default(),
                        no_edit: false,
                        attach: vec![],
                    })?;
                    Ok("added".to_string())
                }));
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
            self.focus = Focus::List;
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
            .split(rows[1]);
        self.draw_list(f, panes[0]);
        self.draw_details(f, panes[1]);
        self.draw_footer(f, rows[2]);

        match &self.mode {
            Mode::Help => draw_help(f, area),
            Mode::Settings(row) => draw_settings(f, area, *row),
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
            format!(" {}/{} ", self.filtered.len(), self.entries.len());
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
        let items: Vec<ListItem> = self
            .filtered
            .iter()
            .map(|&i| {
                let e = &self.entries[i];
                let mut spans = vec![Span::raw(e.name.clone())];
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
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(border)),
            )
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
        let mut meta = vec![Span::styled(entry.kind, Style::new().fg(DIM))];
        if let Some(folder) = &entry.folder {
            meta.push(Span::styled(
                format!(" · {folder}"),
                Style::new().fg(Color::Blue),
            ));
        }
        if entry.attachments > 0 {
            meta.push(Span::styled(
                format!(" · {} attachment(s)", entry.attachments),
                Style::new().fg(DIM),
            ));
        }
        lines.push(Line::from(meta));
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
        let keys: &[(&str, &str)] = if self.focus == Focus::Details {
            &[
                ("↵", "copy"),
                ("^R", "reveal"),
                ("⇥/Esc", "back"),
                ("F1", "help"),
            ]
        } else {
            &[
                ("↵", "copy"),
                ("^U", "user"),
                ("^T", "totp"),
                ("^O", "open"),
                ("⇥", "fields"),
                ("^E", "edit"),
                ("^N", "new"),
                ("F1", "help"),
                ("F2", "security"),
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

fn needs_secret(key: &KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Enter | KeyCode::Tab | KeyCode::Right => true,
        KeyCode::Char('u' | 't' | 'r' | 'e' | 'n' | 'd') => ctrl,
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
        ("↑ ↓  ^P ^K / ^J", "move (PgUp PgDn Home End)"),
        ("Enter", "copy password (card number, note, public key)"),
        ("Tab →", "pick a field, Enter copies it"),
        ("^U  ^T", "copy username, totp code"),
        ("^R", "show or hide secrets"),
        ("^O", "open the web address"),
        ("^E  ^N  ^D", "edit, new (named after the filter), trash"),
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
