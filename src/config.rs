use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    pub client_cert_path: Option<std::path::PathBuf>,
    // when the refresh token stops working, log in again with the personal
    // api key (asked for through the pinentry) instead of requiring a new
    // interactive login with two factor authentication
    #[serde(default)]
    pub persistent_login: bool,
    // show a desktop notification when the agent can no longer reach the
    // vault because the login expired
    #[serde(default = "default_notify")]
    pub notify: bool,
    // lock_timeout 0 never locks: the keys stay until the agent stops
    // also lock when the system wakes up from sleep
    #[serde(default)]
    pub lock_on_sleep: bool,
    // also lock when the session goes idle or the screen locks (logind)
    #[serde(default)]
    pub lock_on_idle: bool,
    // what locking does: keep the keys for a pin or system unlock, or drop
    // them so that the master password is needed
    #[serde(default)]
    pub timeout_action: TimeoutAction,
    // unlock through polkit (face, fingerprint or the account password, as
    // the polkit-1 pam stack decides) instead of the master password
    #[serde(default, alias = "biometric")]
    pub system_auth: bool,
    // where `rbw remember-password` saved the master password, so that pin
    // and system unlock also work for the first unlock after the agent
    // starts
    #[serde(default, alias = "biometric_store")]
    pub saved_password: Option<crate::biometric::SecretStore>,
    // unlock with the saved password without asking anything: the vault is
    // unlocked as soon as something (e.g. a login service) asks for it
    #[serde(default)]
    pub auto_unlock: bool,
    // rbw tui asks polkit (face, fingerprint) once per login session
    #[serde(default)]
    pub tui_auth: bool,
    // list the entries used most often and most recently first
    #[serde(default)]
    pub sort_by_usage: bool,
    // where the tui saves attachments; unset, the user's download folder
    #[serde(default)]
    pub attachments_dir: Option<std::path::PathBuf>,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            client_cert_path: None,
            persistent_login: false,
            notify: default_notify(),
            lock_on_sleep: false,
            lock_on_idle: false,
            timeout_action: TimeoutAction::default(),
            system_auth: false,
            saved_password: None,
            auto_unlock: false,
            tui_auth: false,
            sort_by_usage: false,
            attachments_dir: None,
            device_id: None,
        }
    }
}

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
)]
#[serde(rename_all = "kebab-case")]
pub enum TimeoutAction {
    #[default]
    Lock,
    Forget,
}

impl std::str::FromStr for TimeoutAction {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s {
            "lock" => Ok(Self::Lock),
            "forget" | "logout" => Ok(Self::Forget),
            _ => Err(format!("expected lock or forget, got '{s}'")),
        }
    }
}

impl TimeoutAction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Forget => "forget",
        }
    }
}

// "1h", "90m", "4h", "never"/"restart" (0) or plain seconds
pub fn parse_lock_timeout(value: &str) -> std::result::Result<u64, String> {
    match value {
        "never" | "restart" | "0" => Ok(0),
        _ => value.parse::<u64>().or_else(|_| {
            humantime::parse_duration(value)
                .map(|d| d.as_secs())
                .map_err(|e| format!("invalid lock_timeout '{value}': {e}"))
        }),
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_notify() -> bool {
    true
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    // attachments_dir with a leading ~ expanded, or else the download folder
    // of the user (XDG_DOWNLOAD_DIR on Linux, ~/Downloads on macOS), or else
    // the home
    pub fn attachments_dir(&self) -> std::path::PathBuf {
        let user_dirs = directories::UserDirs::new();
        let home = user_dirs.as_ref().map(|d| d.home_dir().to_path_buf());
        if let Some(dir) = &self.attachments_dir {
            return match (dir.strip_prefix("~"), &home) {
                (Ok(rest), Some(home)) => home.join(rest),
                _ => dir.clone(),
            };
        }
        user_dirs
            .as_ref()
            .and_then(directories::UserDirs::download_dir)
            .map(std::path::Path::to_path_buf)
            .or(home)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        Ok(slf.fix_lock_timeout())
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        Ok(slf.fix_lock_timeout())
    }

    // upstream rejects 0; here it means never, but a lock timeout so long
    // that a timer would overflow is the same thing
    fn fix_lock_timeout(mut self) -> Self {
        if self.lock_timeout > 100 * 365 * 24 * 3600 {
            self.lock_timeout = 0;
        }
        self
    }

    pub fn save(&self) -> Result<()> {
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        // replaced atomically: the agent rereads it while the tui saves
        let tmp = file.with_extension("json.tmp");
        let mut fh = std::fs::File::create(&tmp).map_err(|source| {
            Error::SaveConfig {
                source,
                file: tmp.clone(),
            }
        })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig {
            source,
            file: tmp.clone(),
        })?;
        std::fs::rename(&tmp, &file)
            .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        let id = config.device_id.as_ref().map_or_else(
            || uuid::Uuid::new_v4().hyphenated().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::File::create(&file).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}
