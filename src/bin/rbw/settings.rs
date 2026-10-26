// The tui's settings: the security ones laid out like the official
// clients' (session timeout, timeout action, unlock with pin, unlock with
// system authentication, master password on restart), then the folder the
// tui saves attachments in. Every change is saved right away with `rbw
// config set` and friends, so the cli and the tui never disagree, and the
// running agent picks it up without restarting.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Timeout {
    After(u64),
    Idle,
    Sleep,
    Restart,
    // a combination the cli allows but the list doesn't have
    Custom,
}

const TIMEOUTS: &[Timeout] = &[
    Timeout::After(60),
    Timeout::After(5 * 60),
    Timeout::After(15 * 60),
    Timeout::After(30 * 60),
    Timeout::After(3600),
    Timeout::After(4 * 3600),
    Timeout::Idle,
    Timeout::Sleep,
    Timeout::Restart,
];

pub const ROWS: usize = 8;

// edited as text, not changed with the arrows like the rows above
pub const ATTACHMENTS_ROW: usize = 7;

pub struct Settings {
    pub timeout: Timeout,
    pub lock_timeout: u64,
    pub forget: bool,
    pub pin: bool,
    pub system_auth: bool,
    pub saved_password: bool,
    pub auto_unlock: bool,
    pub tui_auth: bool,
    pub attachments_dir: Option<std::path::PathBuf>,
    // where they actually go
    pub attachments_path: std::path::PathBuf,
}

impl Settings {
    pub fn load() -> Self {
        let config = rbw::config::Config::load().unwrap_or_default();
        let timeout = match (
            config.lock_timeout,
            config.lock_on_idle,
            config.lock_on_sleep,
        ) {
            (0, true, _) => Timeout::Idle,
            (0, false, true) => Timeout::Sleep,
            (0, false, false) => Timeout::Restart,
            (n, false, false) if TIMEOUTS.contains(&Timeout::After(n)) => {
                Timeout::After(n)
            }
            _ => Timeout::Custom,
        };
        Self {
            timeout,
            lock_timeout: config.lock_timeout,
            forget: config.timeout_action
                == rbw::config::TimeoutAction::Forget,
            pin: rbw::pin::is_set(),
            system_auth: config.system_auth,
            saved_password: config.saved_password.is_some(),
            auto_unlock: config.auto_unlock,
            tui_auth: config.tui_auth,
            attachments_path: config.attachments_dir(),
            attachments_dir: config.attachments_dir,
        }
    }

    pub fn timeout_label(&self) -> String {
        match self.timeout {
            Timeout::After(60) => "1 minute".to_string(),
            Timeout::After(3600) => "1 hour".to_string(),
            Timeout::After(n) if n % 3600 == 0 => {
                format!("{} hours", n / 3600)
            }
            Timeout::After(n) => format!("{} minutes", n / 60),
            Timeout::Idle => "when the system is idle".to_string(),
            Timeout::Sleep => "when the system sleeps".to_string(),
            Timeout::Restart => "on restart".to_string(),
            Timeout::Custom => format!(
                "custom ({})",
                if self.lock_timeout == 0 {
                    "no timer".to_string()
                } else {
                    humantime::format_duration(
                        std::time::Duration::from_secs(self.lock_timeout),
                    )
                    .to_string()
                }
            ),
        }
    }

    // what changing a row does, for the line under the list
    pub fn describe(row: usize) -> &'static str {
        match row {
            0 => "when rbw-enhanced locks by itself (idle and sleep come from logind)",
            1 => {
                "lock keeps the keys for a pin or system unlock; log out \
                  needs the master password again"
            }
            2 => "unlock with a pin instead of the master password",
            3 => {
                "unlock through polkit: face (howdy), fingerprint, or your \
                  account password"
            }
            4 => {
                "unchecked: the master password is saved (systemd-creds \
                  or keyring) so pin and system unlock work after a restart"
            }
            5 => {
                "unlock with the saved password without asking: the vault \
                  is open from the desktop login (rofi, scripts)"
            }
            6 => {
                "rbw tui asks polkit (face, fingerprint) once per login \
                  session; rbw get and rofi are not affected"
            }
            _ => {
                "where Enter on an attachment saves it; empty is your \
                  download folder (XDG_DOWNLOAD_DIR)"
            }
        }
    }
}

// a change that runs right away, or one that needs the terminal (pinentry)
pub enum Change {
    Done(anyhow::Result<String>),
    Prompt(Box<dyn FnOnce() -> anyhow::Result<String>>),
}

fn set(key: &str, value: &str) -> anyhow::Result<()> {
    crate::commands::config_set(key, value)
}

fn set_timeout(timeout: Timeout) -> anyhow::Result<String> {
    let (secs, idle, sleep) = match timeout {
        Timeout::After(n) => (n.to_string(), false, false),
        Timeout::Idle => ("never".to_string(), true, true),
        Timeout::Sleep => ("never".to_string(), false, true),
        Timeout::Restart | Timeout::Custom => {
            ("never".to_string(), false, false)
        }
    };
    set("lock_timeout", &secs)?;
    set("lock_on_idle", if idle { "true" } else { "false" })?;
    set("lock_on_sleep", if sleep { "true" } else { "false" })?;
    Ok("session timeout saved".to_string())
}

// step: +1 / -1 for the choice rows, ignored by the checkboxes
pub fn change(settings: &Settings, row: usize, step: isize) -> Change {
    match row {
        0 => {
            let pos = TIMEOUTS.iter().position(|t| *t == settings.timeout);
            // from a custom timeout, start from 1 hour
            let next = pos.map_or(4, |p| {
                p.saturating_add_signed(step).min(TIMEOUTS.len() - 1)
            });
            Change::Done(set_timeout(TIMEOUTS[next]))
        }
        1 => Change::Done(
            set(
                "timeout_action",
                if settings.forget { "lock" } else { "forget" },
            )
            .map(|()| "timeout action saved".to_string()),
        ),
        2 => {
            if settings.pin {
                Change::Done(
                    crate::commands::pin_clear()
                        .map(|()| "pin removed".to_string()),
                )
            } else {
                Change::Prompt(Box::new(|| {
                    crate::commands::pin_set()?;
                    Ok("pin set".to_string())
                }))
            }
        }
        3 => Change::Done(
            set(
                "system_auth",
                if settings.system_auth {
                    "false"
                } else {
                    "true"
                },
            )
            .map(|()| "system authentication saved".to_string()),
        ),
        4 => {
            if settings.saved_password {
                Change::Done(
                    crate::commands::forget_password().map(|()| {
                        "saved master password deleted".to_string()
                    }),
                )
            } else {
                Change::Prompt(Box::new(|| {
                    crate::commands::remember_password(None)?;
                    Ok("master password saved".to_string())
                }))
            }
        }
        5 => {
            if settings.auto_unlock {
                Change::Done(
                    set("auto_unlock", "false")
                        .map(|()| "automatic unlock off".to_string()),
                )
            } else if settings.saved_password {
                Change::Done(
                    set("auto_unlock", "true")
                        .map(|()| "automatic unlock on".to_string()),
                )
            } else {
                // it needs the saved password: save it first
                Change::Prompt(Box::new(|| {
                    crate::commands::remember_password(None)?;
                    set("auto_unlock", "true")?;
                    Ok("master password saved, automatic unlock on"
                        .to_string())
                }))
            }
        }
        6 => Change::Done(
            set("tui_auth", if settings.tui_auth { "false" } else { "true" })
                .map(|()| "tui authentication saved".to_string()),
        ),
        // the attachments folder is typed, see ATTACHMENTS_ROW
        _ => Change::Done(Ok(String::new())),
    }
}
