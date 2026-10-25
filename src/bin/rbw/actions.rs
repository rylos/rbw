use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

use anyhow::Context as _;

pub fn register() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register)
}

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login)
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock)
}

pub fn unlocked() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::CheckLock,
            ))?;

            let res = sock.recv()?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) {
                anyhow::bail!("agent not running");
            }
            Err(e.into())
        }
    }
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock(hard: bool) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock { hard })
}

// None when the agent isn't running; never starts it
pub fn status() -> anyhow::Result<Option<rbw::protocol::Status>> {
    let mut sock = match crate::sock::Sock::connect() {
        Ok(sock) => sock,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) =>
        {
            return Ok(None)
        }
        Err(e) => return Err(e.into()),
    };
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Status,
    ))?;
    match sock.recv()? {
        rbw::protocol::Response::Status(status) => Ok(Some(status)),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
        res => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn biometric_enroll(
    store: Option<rbw::biometric::SecretStore>,
) -> anyhow::Result<rbw::biometric::SecretStore> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::BiometricEnroll { store },
    ))?;
    match sock.recv()? {
        rbw::protocol::Response::BiometricEnroll { store } => Ok(store),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
        res => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn biometric_disable() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::BiometricDisable)
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) =
                rustix::process::Pid::from_raw(pid.trim_end().parse()?)
            else {
                anyhow::bail!("failed to read pid from pidfile");
            };
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::Quit,
            ))?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn decrypt(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

// decrypt a batch of cipherstrings with a single agent round trip; each
// item succeeds or fails individually
pub fn decrypt_many(
    items: Vec<rbw::protocol::DecryptItem>,
) -> anyhow::Result<Vec<Result<String, String>>> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::DecryptMany { items },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::DecryptMany { plaintexts } => Ok(plaintexts),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn encrypt(
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    encrypt_for_entry(plaintext, None, org_id)
}

pub fn encrypt_for_entry(
    plaintext: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Encrypt {
            plaintext: plaintext.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
            entry_key: entry_key.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

// returns the new attachment's encrypted key and its encrypted contents
pub fn encrypt_attachment(
    data: &[u8],
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::EncryptAttachment {
            data: rbw::base64::encode(data),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::EncryptAttachment { key, data } => Ok((
            key,
            rbw::base64::decode(data)
                .context("agent returned invalid base64")?,
        )),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt attachment: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn decrypt_attachment(
    data: &[u8],
    key: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::DecryptAttachment {
            data: rbw::base64::encode(data),
            key: key.map(std::string::ToString::to_string),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::DecryptAttachment { data } => {
            rbw::base64::decode(data).context("agent returned invalid base64")
        }
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt attachment: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn refresh_token() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::RefreshToken)
}

pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ClipboardStore {
        text: text.to_string(),
    })
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Version,
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::new(get_environment(), action))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn connect() -> anyhow::Result<crate::sock::Sock> {
    crate::sock::Sock::connect().with_context(|| {
        let log = rbw::dirs::agent_stderr_file();
        format!(
            "failed to connect to rbw-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.display()
        )
    })
}

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}
