// Unlocking without typing the master password.
//
// Biometrics can't derive the vault key, they can only authorize something.
// The agent asks polkit for the `net.rbw.unlock` action: polkit runs the
// `polkit-1` PAM stack as root, so a face (howdy) or fingerprint (fprintd)
// module there works, and the user's polkit agent shows the dialog. Once the
// action is authorized the agent either reuses the keys it kept in memory
// when it was locked, or, for the first unlock after it started, reads the
// master password saved with `rbw remember-password`.
//
// The saved password is encrypted with systemd-creds, scoped to the user and
// tied to this machine (TPM2 plus the host key when there is a TPM, the host
// key alone otherwise), or kept in the Secret Service (KWallet,
// gnome-keyring) where systemd-creds isn't available. Either way any process
// running as the user can read it back: biometrics protect against someone at
// the keyboard, not against malware running as the user, exactly like a
// password kept in the keyring for a pinentry wrapper.

use crate::prelude::*;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const POLKIT_ACTION: &str = "net.rbw.unlock";

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
#[serde(rename_all = "kebab-case")]
pub enum SecretStore {
    SystemdCreds,
    SecretService,
}

impl SecretStore {
    pub fn name(self) -> &'static str {
        match self {
            Self::SystemdCreds => "systemd-creds",
            Self::SecretService => "secret-service",
        }
    }
}

impl std::str::FromStr for SecretStore {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "systemd-creds" => Ok(Self::SystemdCreds),
            "secret-service" => Ok(Self::SecretService),
            _ => Err(Error::Biometric {
                message: format!(
                    "unknown secret store '{s}' \
                     (use systemd-creds or secret-service)"
                ),
            }),
        }
    }
}

fn err(message: impl Into<String>) -> Error {
    Error::Biometric {
        message: message.into(),
    }
}

fn credential_name() -> String {
    format!("{}-master", crate::dirs::profile())
}

// not the "master" item pinentry wrappers commonly read, so that
// `rbw forget-password` never deletes something it didn't create
fn secret_service_account() -> String {
    format!("{}-biometric", crate::dirs::profile())
}

async fn command_exists(cmd: &str) -> bool {
    tokio::process::Command::new(cmd)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok()
}

// whether the polkit action is installed (the policy file needs root)
pub async fn polkit_available() -> bool {
    tokio::process::Command::new("pkaction")
        .args(["--action-id", POLKIT_ACTION])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

pub async fn has_tpm2() -> bool {
    tokio::process::Command::new("systemd-analyze")
        .arg("has-tpm2")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

// the store to use when the user didn't pick one
pub async fn default_store() -> Option<SecretStore> {
    if systemd_creds_works().await {
        Some(SecretStore::SystemdCreds)
    } else if command_exists("secret-tool").await {
        Some(SecretStore::SecretService)
    } else {
        None
    }
}

// user scoped credentials need systemd 256 or newer
async fn systemd_creds_works() -> bool {
    let Ok(mut child) = tokio::process::Command::new("systemd-creds")
        .args(["encrypt", "--user", "--with-key=auto", "--name=rbw-probe"])
        .args(["-", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"probe").await;
    }
    child.wait().await.is_ok_and(|s| s.success())
}

// asks polkit to authorize the unlock for the given process (the client that
// asked, so that its session's polkit agent shows the dialog). Ok(false)
// means the user dismissed the dialog or failed to authenticate.
pub async fn authorize(pid: u32) -> Result<bool> {
    let status = tokio::process::Command::new("pkcheck")
        .args(["--action-id", POLKIT_ACTION, "--process"])
        .arg(pid.to_string())
        .arg("--allow-user-interaction")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|e| err(format!("failed to run {e}")))?;
    Ok(status.success())
}

pub async fn store(
    store: SecretStore,
    password: &crate::locked::Password,
) -> Result<()> {
    match store {
        SecretStore::SystemdCreds => {
            let file = crate::dirs::biometric_credential_file();
            let tmp = file.with_extension("tmp");
            let mut child = tokio::process::Command::new("systemd-creds")
                .args(["encrypt", "--user", "--with-key=auto"])
                .arg(format!("--name={}", credential_name()))
                .arg("-")
                .arg(&tmp)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| err(format!("failed to run {e}")))?;
            write_and_wait(&mut child, password.password(), "systemd-creds")
                .await?;
            tokio::fs::rename(&tmp, &file).await.map_err(|e| {
                err(format!("failed to save {}: {e}", file.display()))
            })?;
        }
        SecretStore::SecretService => {
            let mut child = tokio::process::Command::new("secret-tool")
                .args(["store", "--label=rbw master password"])
                .args(["service", "rbw", "account"])
                .arg(secret_service_account())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| err(format!("failed to run {e}")))?;
            write_and_wait(&mut child, password.password(), "secret-tool")
                .await?;
        }
    }
    Ok(())
}

async fn write_and_wait(
    child: &mut tokio::process::Child,
    data: &[u8],
    what: &str,
) -> Result<()> {
    // unwrap is safe because stdin is piped in the callers
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(data)
        .await
        .map_err(|e| err(format!("failed to write to {what}: {e}")))?;
    drop(stdin);
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr).await;
    }
    let status = child
        .wait()
        .await
        .map_err(|e| err(format!("failed to wait for {what}: {e}")))?;
    if !status.success() {
        return Err(err(format!("{what} failed: {}", stderr.trim())));
    }
    Ok(())
}

// the saved master password, None when nothing was saved
pub async fn load(
    store: SecretStore,
) -> Result<Option<crate::locked::Password>> {
    let mut cmd = match store {
        SecretStore::SystemdCreds => {
            let file = crate::dirs::biometric_credential_file();
            if !file.exists() {
                return Ok(None);
            }
            let mut cmd = tokio::process::Command::new("systemd-creds");
            cmd.args(["decrypt", "--user"])
                .arg(format!("--name={}", credential_name()))
                .arg(file)
                .arg("-");
            cmd
        }
        SecretStore::SecretService => {
            let mut cmd = tokio::process::Command::new("secret-tool");
            cmd.args(["lookup", "service", "rbw", "account"])
                .arg(secret_service_account());
            cmd
        }
    };
    let out = cmd
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| err(format!("failed to run {e}")))?;
    let mut stdout = out.stdout;
    let res = if out.status.success() && !stdout.is_empty() {
        let mut password = crate::locked::Vec::new();
        password.extend(stdout.iter().copied());
        Ok(Some(crate::locked::Password::new(password)))
    } else if store == SecretStore::SystemdCreds {
        Err(err("systemd-creds couldn't decrypt the saved password"))
    } else {
        Ok(None)
    };
    zeroize::Zeroize::zeroize(&mut stdout);
    res
}

pub async fn forget(store: SecretStore) -> Result<()> {
    match store {
        SecretStore::SystemdCreds => {
            let file = crate::dirs::biometric_credential_file();
            match tokio::fs::remove_file(&file).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(err(format!(
                    "failed to remove {}: {e}",
                    file.display()
                ))),
            }
        }
        SecretStore::SecretService => {
            let status = tokio::process::Command::new("secret-tool")
                .args(["clear", "service", "rbw", "account"])
                .arg(secret_service_account())
                .stdin(std::process::Stdio::null())
                .status()
                .await
                .map_err(|e| err(format!("failed to run {e}")))?;
            if status.success() {
                Ok(())
            } else {
                Err(err("secret-tool clear failed"))
            }
        }
    }
}
