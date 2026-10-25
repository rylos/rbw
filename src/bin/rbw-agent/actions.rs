use anyhow::Context as _;

// Requests are handled concurrently, so two commands started together (a
// script and rofi-rbw, say) would each find the agent locked, or the access
// token expired, and each open its own pinentry. These serialize everything
// that asks for credentials; whoever comes second checks again and usually
// finds the work done. Always taken in this order: LOGIN, TOKEN, UNLOCK.
static LOGIN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static TOKEN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static UNLOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let _login = LOGIN.lock().await;
    let db = load_db_or_new().await?;

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let _login = LOGIN.lock().await;
    let db = load_db_or_new().await?;

    if db.needs_login() && config_persistent_login().await? {
        // the api key skips two factor authentication; the master password
        // is still needed to unlock the keys
        let res = {
            let _token = TOKEN.lock().await;
            api_key_login(state.clone(), Some(environment)).await
        };
        match res {
            Ok(_) => {
                sync(None, state.clone()).await?;
                unlock_state(state, environment, sock.peer_pid()).await?;
                respond_ack(sock).await?;
                return Ok(());
            }
            Err(e) => {
                log::warn!(
                    "api key login failed, falling back to password login: \
                     {e:#}"
                );
            }
        }
    }

    let db = load_db_or_new().await?;

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        'attempts: for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::login(&email, password.clone(), None, None)
                .await
            {
                Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                )) => {
                    login_success(
                        state.clone(),
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                        password,
                        db,
                        email,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(rbw::error::Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        rbw::api::TwoFactorProviderType::Authenticator,
                        rbw::api::TwoFactorProviderType::Yubikey,
                        rbw::api::TwoFactorProviderType::Email,
                    ];

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == rbw::api::TwoFactorProviderType::Email
                            {
                                if let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                                {
                                    rbw::actions::send_two_factor_email(
                                        &email,
                                        &sso_email_2fa_session_token,
                                    )
                                    .await?;
                                }
                            }
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                            ) = two_factor(
                                environment,
                                &email,
                                password.clone(),
                                provider,
                            )
                            .await?;
                            login_success(
                                state.clone(),
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                                password,
                                db,
                                email,
                            )
                            .await?;
                            break 'attempts;
                        }
                    }
                    return Err(anyhow::anyhow!(
                        "unsupported two factor methods: {providers:?}"
                    ));
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn two_factor(
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = rbw::pinentry::getpin(
            &config_pinentry().await?,
            provider.header(),
            provider.message(),
            err.as_deref(),
            environment,
            provider.grab(),
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    mut db: rbw::db::Db,
    email: String,
) -> anyhow::Result<()> {
    db.access_token = Some(access_token.clone());
    db.refresh_token = Some(refresh_token.clone());
    db.api_key_login = false;
    db.kdf = Some(kdf);
    db.iterations = Some(iterations);
    db.memory = memory;
    db.parallelism = parallelism;
    db.protected_key = Some(protected_key.clone());
    save_db(&db).await?;

    sync(None, state.clone()).await?;
    let db = load_db().await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            let mut state = state.lock().await;
            state.priv_key = Some(keys);
            state.org_keys = Some(org_keys);
            state.soft_locked = false;
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    peer: Option<u32>,
) -> anyhow::Result<()> {
    let _unlock = UNLOCK.lock().await;
    if !state.lock().await.needs_unlock() {
        return Ok(());
    }

    let settings = state.lock().await.settings;
    let reusable =
        state.lock().await.has_keys() || settings.saved_password.is_some();
    if settings.auto_unlock && settings.saved_password.is_some() {
        match reuse_keys(state.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => log::warn!("auto unlock failed: {e:#}"),
        }
    }
    if reusable && settings.system_auth {
        match system_unlock(state.clone(), peer).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => log::warn!("system unlock failed: {e:#}"),
        }
    }
    if reusable && settings.pin {
        match pin_unlock(state.clone(), environment).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => log::warn!("pin unlock failed: {e:#}"),
        }
    }

    let db = load_db().await?;
    let email = config_email().await?;

    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop
            // if we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let password = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Master Password",
            &format!(
                "Unlock the local database for '{}'",
                rbw::dirs::profile()
            ),
            err.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        match unlock_keys(&db, &email, &password)? {
            Ok((keys, org_keys)) => {
                unlock_success(state, keys, org_keys).await?;
                break;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to unlock database");
                }
                err_msg = Some(message);
            }
            Err(e) => return Err(e).context("failed to unlock database"),
        }
    }

    Ok(())
}

// the outer error is a db without the data needed to unlock, the inner one
// comes from the unlock itself (so that a wrong password can be retried)
fn unlock_keys(
    db: &rbw::db::Db,
    email: &str,
    password: &rbw::locked::Password,
) -> anyhow::Result<
    Result<
        (
            rbw::locked::Keys,
            std::collections::HashMap<String, rbw::locked::Keys>,
        ),
        rbw::error::Error,
    >,
> {
    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };
    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };
    let Some(protected_key) = &db.protected_key else {
        return Err(anyhow::anyhow!("failed to find protected key in db"));
    };
    let Some(protected_private_key) = &db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };
    Ok(rbw::actions::unlock(
        email,
        password,
        kdf,
        iterations,
        db.memory,
        db.parallelism,
        protected_key,
        protected_private_key,
        &db.protected_org_keys,
    ))
}

// after a system or pin unlock: start using the kept keys again, or unlock
// with the saved master password
async fn reuse_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    {
        let mut state = state.lock().await;
        if state.has_keys() {
            state.soft_locked = false;
            state.pin_failures = 0;
            return Ok(());
        }
    }

    let Some(store) = state.lock().await.settings.saved_password else {
        return Err(anyhow::anyhow!("no saved master password"));
    };
    let Some(password) = rbw::biometric::load(store).await? else {
        return Err(anyhow::anyhow!(
            "no master password saved in {}, run `rbw remember-password`",
            store.name()
        ));
    };
    let db = load_db().await?;
    let email = config_email().await?;
    match unlock_keys(&db, &email, &password)? {
        Ok((keys, org_keys)) => unlock_success(state, keys, org_keys).await,
        Err(rbw::error::Error::IncorrectPassword { .. }) => {
            Err(anyhow::anyhow!(
                "the saved master password is wrong (changed?), run \
                 `rbw remember-password` again"
            ))
        }
        Err(e) => Err(e).context("failed to unlock database"),
    }
}

// Ok(false) when the user didn't authorize it: the caller then tries the pin
// or the master password
async fn system_unlock(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    peer: Option<u32>,
) -> anyhow::Result<bool> {
    if !rbw::biometric::polkit_available().await {
        return Err(anyhow::anyhow!(
            "the polkit action {} is not installed",
            rbw::biometric::POLKIT_ACTION
        ));
    }
    let pid = peer.unwrap_or_else(std::process::id);
    if !rbw::biometric::authorize(pid).await? {
        log::info!("system unlock not authorized");
        return Ok(false);
    }
    reuse_keys(state).await?;
    Ok(true)
}

// Ok(false) when the pinentry was cancelled or too many wrong pins were
// given (then the kept keys are dropped)
async fn pin_unlock(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<bool> {
    let mut err_msg: Option<String> = None;
    loop {
        let failures = state.lock().await.pin_failures;
        if failures >= rbw::pin::MAX_FAILURES {
            return Ok(false);
        }
        let pin = match rbw::pinentry::getpin(
            &config_pinentry().await?,
            "PIN",
            &format!(
                "Unlock '{}' with your PIN (cancel for the master password)",
                rbw::dirs::profile()
            ),
            err_msg.as_deref(),
            environment,
            true,
        )
        .await
        {
            Ok(pin) => pin,
            Err(rbw::error::Error::PinentryCancelled) => return Ok(false),
            Err(e) => return Err(e).context("failed to read the pin"),
        };
        if rbw::pin::verify(&pin)? {
            reuse_keys(state).await?;
            return Ok(true);
        }
        let mut state_guard = state.lock().await;
        state_guard.pin_failures += 1;
        let left = rbw::pin::MAX_FAILURES - state_guard.pin_failures;
        if left == 0 {
            log::warn!("too many wrong pins, the master password is needed");
            state_guard.forget_keys();
            return Ok(false);
        }
        drop(state_guard);
        err_msg = Some(format!("Wrong PIN ({left} attempts left)"));
    }
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_state(state, environment, sock.peer_pid()).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    state.soft_locked = false;
    state.pin_failures = 0;
    Ok(())
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    hard: bool,
) -> anyhow::Result<()> {
    if hard {
        state.lock().await.forget_keys();
    } else {
        state.lock().await.clear();
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn status(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let status = {
        let state = state.lock().await;
        rbw::protocol::Status {
            locked: state.needs_unlock(),
            keys_in_memory: state.soft_locked && state.has_keys(),
            system_auth: state.settings.system_auth,
            pin: state.settings.pin,
            saved_password: state.settings.saved_password.is_some(),
            login_expired: state.login_expired_notified,
        }
    };
    sock.send(&rbw::protocol::Response::Status(status)).await?;

    Ok(())
}

pub async fn remember_password(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    store: Option<rbw::biometric::SecretStore>,
) -> anyhow::Result<()> {
    let store = match store {
        Some(store) => store,
        None => rbw::biometric::default_store().await.ok_or_else(|| {
            anyhow::anyhow!(
                "neither systemd-creds (systemd 256 or newer) nor \
                 secret-tool is available to save the master password"
            )
        })?,
    };

    let db = load_db().await?;
    let email = config_email().await?;
    let mut err_msg: Option<String> = None;
    let password = loop {
        let password = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Master Password",
            "Save the master password for pin and system unlock",
            err_msg.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        match unlock_keys(&db, &email, &password)? {
            Ok((keys, org_keys)) => {
                unlock_success(state.clone(), keys, org_keys).await?;
                break password;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if err_msg.is_some() {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to verify the master password");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e).context("failed to verify the master password")
            }
        }
    };

    rbw::biometric::store(store, &password).await?;
    // make sure it reads back before relying on it
    let saved = rbw::biometric::load(store).await?;
    if saved.as_ref().map(rbw::locked::Password::password)
        != Some(password.password())
    {
        let _ = rbw::biometric::forget(store).await;
        return Err(anyhow::anyhow!(
            "the password saved in {} didn't read back",
            store.name()
        ));
    }

    state.lock().await.settings.saved_password = Some(store);
    sock.send(&rbw::protocol::Response::RememberPassword { store })
        .await?;

    Ok(())
}

pub async fn forget_password(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let store = state.lock().await.settings.saved_password;
    if let Some(store) = store {
        rbw::biometric::forget(store).await?;
    }
    state.lock().await.settings.saved_password = None;

    respond_ack(sock).await?;

    Ok(())
}

pub async fn pin_set(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }
    let pinentry = config_pinentry().await?;
    let mut err_msg: Option<&str> = None;
    let pin = loop {
        let pin = rbw::pinentry::getpin(
            &pinentry,
            "PIN",
            "Choose a PIN to unlock rbw",
            err_msg,
            environment,
            true,
        )
        .await
        .context("failed to read the pin")?;
        if pin.password().is_empty() {
            err_msg = Some("The PIN can't be empty");
            continue;
        }
        let again = rbw::pinentry::getpin(
            &pinentry,
            "PIN",
            "Type the same PIN again",
            None,
            environment,
            true,
        )
        .await
        .context("failed to read the pin")?;
        if again.password() == pin.password() {
            break pin;
        }
        err_msg = Some("The PINs didn't match, choose one again");
    };
    rbw::pin::set(&pin)?;
    let mut state = state.lock().await;
    state.settings.pin = true;
    state.pin_failures = 0;
    drop(state);

    respond_ack(sock).await?;

    Ok(())
}

pub async fn pin_clear(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    rbw::pin::clear()?;
    let mut state = state.lock().await;
    state.settings.pin = false;
    // a lock that kept the keys for the pin must not keep them now
    if state.soft_locked && !state.settings.quick_unlock() {
        state.forget_keys();
    }
    drop(state);

    respond_ack(sock).await?;

    Ok(())
}

// the login session of a process (logind's session id, as the kernel keeps
// it for audit); None outside a session
fn session_of(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/sessionid"))
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|&id| id != u32::MAX)
}

// tui_auth: polkit once per login session. A convenience gate for the tui,
// not a security boundary: with the vault unlocked, rbw get works anyway.
pub async fn authorize_tui(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let Some(pid) = sock.peer_pid() else {
        return Err(anyhow::anyhow!("couldn't identify the tui process"));
    };
    let session = session_of(pid);
    if session.is_some() && state.lock().await.tui_session == session {
        return respond_ack(sock).await;
    }
    if !rbw::biometric::polkit_available().await {
        return Err(anyhow::anyhow!(
            "the polkit action {} is not installed",
            rbw::biometric::POLKIT_ACTION
        ));
    }
    if !rbw::biometric::authorize(pid).await? {
        return Err(anyhow::anyhow!("not authorized"));
    }
    state.lock().await.tui_session = session;
    respond_ack(sock).await
}

pub async fn reload_config(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    let mut state = state.lock().await;
    state.settings = crate::state::Settings::from_config(&config);
    state.timeout_duration =
        std::time::Duration::from_secs(config.lock_timeout);
    if state.soft_locked && !state.settings.quick_unlock() {
        state.forget_keys();
    }
    if !state.needs_unlock() {
        state.set_timeout();
    }
    drop(state);

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let db = load_db().await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else if db.protected_key.is_some() && config_persistent_login().await? {
        // logged in before, but the tokens were dropped
        fresh_access_token(state.clone(), None, None).await?
    } else {
        return Err(anyhow::anyhow!("failed to find access token in db"));
    };
    let data = match rbw::actions::sync_once(&access_token).await {
        Ok(res) => res,
        Err(rbw::error::Error::RequestUnauthorized) => {
            let access_token =
                fresh_access_token(state.clone(), None, Some(&access_token))
                    .await?;
            rbw::actions::sync_once(&access_token)
                .await
                .context("failed to sync database from server")?
        }
        Err(e) => {
            return Err(e).context("failed to sync database from server")
        }
    };
    {
        let mut state = state.lock().await;
        state.set_master_password_reprompt(&data.entries);
        state.login_expired_notified = false;
        // organizations joined (or created) since the unlock
        let known = state.org_keys.as_ref().map(|keys| {
            data.protected_org_keys
                .keys()
                .all(|id| keys.contains_key(id))
        });
        if known == Some(false) {
            if let Some(key) = &state.priv_key {
                match rbw::actions::decrypt_org_keys(
                    key,
                    &data.protected_private_key,
                    &data.protected_org_keys,
                ) {
                    Ok(org_keys) => state.org_keys = Some(org_keys),
                    Err(e) => {
                        eprintln!("failed to decrypt the new org keys: {e}");
                    }
                }
            }
        }
    }
    // the tokens may have been replaced while syncing
    let mut db = load_db().await?;
    db.protected_key = Some(data.protected_key);
    db.protected_private_key = Some(data.protected_private_key);
    db.protected_org_keys = data.protected_org_keys;
    db.entries = data.entries;
    db.organizations = data.organizations;
    db.collections = data.collections;
    db.folders = data.folders;
    save_db(&db).await?;

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let Some(keys) = state.key(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };

    if state.needs_master_password_reprompt(cipherstring) {
        master_password_reprompt(environment).await?;
    }

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let plaintext = String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys, entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}

// asks for the master password again before giving out a value of an entry
// that has master password reprompt enabled
async fn master_password_reprompt(
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await?;

    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };

    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };

    let memory = db.memory;
    let parallelism = db.parallelism;

    let Some(protected_key) = db.protected_key else {
        return Err(anyhow::anyhow!("failed to find protected key in db"));
    };
    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let email = config_email().await?;

    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop
            // if we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let password = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Master Password",
            "Accessing this entry requires the master password",
            err.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        match rbw::actions::unlock(
            &email,
            &password,
            kdf,
            iterations,
            memory,
            parallelism,
            &protected_key,
            &protected_private_key,
            &db.protected_org_keys,
        ) {
            Ok(_) => {
                break;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to unlock database");
                }
                err_msg = Some(message);
            }
            Err(e) => return Err(e).context("failed to unlock database"),
        }
    }

    Ok(())
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let plaintext =
        decrypt_cipher(state, environment, cipherstring, entry_key, org_id)
            .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn decrypt_many(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    items: &[rbw::protocol::DecryptItem],
) -> anyhow::Result<()> {
    let mut plaintexts = Vec::with_capacity(items.len());
    for item in items {
        plaintexts.push(
            decrypt_cipher(
                state.clone(),
                environment,
                &item.cipherstring,
                item.entry_key.as_deref(),
                item.org_id.as_deref(),
            )
            .await
            .map_err(|e| format!("{e:#}")),
        );
    }
    sock.send(&rbw::protocol::Response::DecryptMany { plaintexts })
        .await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let keys = entry_keys(&state, entry_key, org_id)?;
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        &keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

// the keys that an entry's values are encrypted with: its own key if it has
// one, otherwise the key of its organization or of the user
fn entry_keys(
    state: &crate::state::State,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<rbw::locked::Keys> {
    let Some(keys) = state.key(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Ok(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        Ok(keys.clone())
    }
}

pub async fn encrypt_attachment(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    data: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let data = rbw::base64::decode(data).context("invalid base64")?;
    let state = state.lock().await;
    let keys = entry_keys(&state, entry_key, org_id)?;

    let attachment_key = rbw::cipherstring::random_key();
    let mut raw_key = rbw::locked::Vec::new();
    raw_key.extend(attachment_key.enc_key().iter().copied());
    raw_key.extend(attachment_key.mac_key().iter().copied());
    let key = rbw::cipherstring::CipherString::encrypt_symmetric(
        &keys,
        raw_key.data(),
    )
    .context("failed to encrypt attachment key")?;
    let encrypted = rbw::cipherstring::encrypt_bytes(&attachment_key, &data)
        .context("failed to encrypt attachment")?;

    sock.send(&rbw::protocol::Response::EncryptAttachment {
        key: key.to_string(),
        data: rbw::base64::encode(encrypted),
    })
    .await?;

    Ok(())
}

pub async fn decrypt_attachment(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    data: &str,
    key: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let data = rbw::base64::decode(data).context("invalid base64")?;
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let keys = entry_keys(&state, entry_key, org_id)?;
    let attachment_key = if let Some(key) = key {
        if state.needs_master_password_reprompt(key) {
            master_password_reprompt(environment).await?;
        }
        rbw::locked::Keys::new(
            rbw::cipherstring::CipherString::new(key)
                .context("failed to parse attachment key")?
                .decrypt_locked_symmetric(&keys)
                .context("failed to decrypt attachment key")?,
        )
    } else {
        keys
    };
    let plaintext = rbw::cipherstring::decrypt_bytes(&attachment_key, &data)
        .context("failed to decrypt attachment")?;

    sock.send(&rbw::protocol::Response::DecryptAttachment {
        data: rbw::base64::encode(plaintext),
    })
    .await?;

    Ok(())
}

pub async fn refresh_token(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    fresh_access_token(state, Some(environment), None).await?;

    respond_ack(sock).await?;

    Ok(())
}

// Gets a new access token and stores it in the db. The refresh token is
// tried first; with persistent_login, an api key login takes over when there
// is no refresh token or the server rejects it. `rejected` is the token the
// caller saw refused: if the db holds another one by now, a concurrent
// request already got it.
async fn fresh_access_token(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: Option<&rbw::protocol::Environment>,
    rejected: Option<&str>,
) -> anyhow::Result<String> {
    let _token = TOKEN.lock().await;
    let persistent_login = config_persistent_login().await?;
    let mut db = load_db().await?;
    if let (Some(rejected), Some(current)) = (rejected, &db.access_token) {
        if current != rejected {
            return Ok(current.clone());
        }
    }

    if let Some(refresh_token) = db.refresh_token.clone() {
        match rbw::actions::exchange_refresh_token_async(&refresh_token).await
        {
            Ok(tokens) => {
                db.access_token = Some(tokens.access_token.clone());
                if let Some(refresh_token) = tokens.refresh_token {
                    db.refresh_token = Some(refresh_token);
                }
                save_db(&db).await?;
                return Ok(tokens.access_token);
            }
            // The server will never accept this refresh token again, so
            // retrying on the sync interval only repeats the same rejection
            // forever. Drop the tokens instead: that makes db.needs_login()
            // true, so the next command the user runs goes through the
            // ordinary login flow, and the syncs in between fail locally
            // without touching the network.
            Err(rbw::error::Error::RefreshTokenInvalid) => {
                // Re-read rather than trusting the copy loaded above: a
                // concurrent sync may have rotated the token while this
                // request was in flight, in which case the server is
                // rejecting a token that has already been superseded and
                // the stored replacement is valid. Only clear if what we
                // sent is still what is stored.
                let mut current = load_db().await?;
                if current.refresh_token.as_deref()
                    == Some(refresh_token.as_str())
                {
                    current.access_token = None;
                    current.refresh_token = None;
                    current.api_key_login = false;
                    save_db(&current).await?;
                } else if let Some(access_token) = current.access_token {
                    return Ok(access_token);
                }
                if !persistent_login {
                    login_expired(&state).await;
                    return Err(rbw::error::Error::RefreshTokenInvalid)
                        .context("failed to refresh access token");
                }
            }
            Err(e) => {
                return Err(e).context("failed to refresh access token")
            }
        }
    } else if !persistent_login {
        login_expired(&state).await;
        return Err(anyhow::anyhow!("failed to find refresh token in db"));
    }

    match api_key_login(state.clone(), environment).await {
        Ok(access_token) => Ok(access_token),
        Err(e) => {
            login_expired(&state).await;
            Err(e)
        }
    }
}

// Logs in with the personal api key and stores the new access token. The
// key is asked for through the pinentry (so a wrapper can answer from a
// keyring) and kept in memory for the next time the token expires.
async fn api_key_login(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: Option<&rbw::protocol::Environment>,
) -> anyhow::Result<String> {
    let email = config_email().await?;
    let cached = state.lock().await.api_key.clone();
    let apikey = if let Some(apikey) = cached {
        apikey
    } else {
        let environment = match environment {
            Some(environment) => environment.clone(),
            None => state.lock().await.last_environment().clone(),
        };
        let host = config_host().await?;
        let client_id = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "API key client__id",
            &format!("Log in to {host}"),
            None,
            &environment,
            false,
        )
        .await
        .context("failed to read client_id from pinentry")?;
        let client_secret = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "API key client__secret",
            &format!("Log in to {host}"),
            None,
            &environment,
            false,
        )
        .await
        .context("failed to read client_secret from pinentry")?;
        rbw::locked::ApiKey::new(client_id, client_secret)
    };

    let login = match rbw::actions::login_api_key(&email, &apikey).await {
        Ok(login) => login,
        Err(e) => {
            // keep the key through network errors and rate limits, forget
            // it when the server rejects it
            if matches!(
                e,
                rbw::error::Error::IncorrectPassword { .. }
                    | rbw::error::Error::RequestFailed { status: 400 | 401 }
            ) {
                state.lock().await.api_key = None;
            }
            return Err(e).context("failed to log in with the api key");
        }
    };

    let mut db = load_db_or_new().await?;
    db.access_token = Some(login.access_token.clone());
    db.refresh_token = None;
    db.api_key_login = true;
    db.kdf = Some(login.kdf);
    db.iterations = Some(login.iterations);
    db.memory = login.memory;
    db.parallelism = login.parallelism;
    db.protected_key = Some(login.key);
    save_db(&db).await?;

    state.lock().await.api_key = Some(apikey);

    Ok(login.access_token)
}

// tells the user (once, until the next successful sync) that the agent can
// no longer reach the vault on its own
async fn login_expired(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) {
    let mut state = state.lock().await;
    if state.login_expired_notified {
        return;
    }
    state.login_expired_notified = true;
    if !config_notify().await.unwrap_or(false) {
        return;
    }
    let env = state.last_environment().env_vars();
    drop(state);
    let profile = rbw::dirs::profile();
    let body = profile.strip_prefix("rbw-").map_or_else(
        || {
            "The local copy of the vault is no longer synced. Run \
             `rbw login`."
                .to_string()
        },
        |profile| {
            format!(
                "The local copy of the vault is no longer synced. Run \
                 `RBW_PROFILE={profile} rbw login`."
            )
        },
    );
    let res = tokio::process::Command::new("notify-send")
        .args(["--app-name=rbw", "--urgency=critical", "rbw: login expired"])
        .arg(body)
        .envs(env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    if let Err(e) = res {
        log::warn!("failed to run notify-send: {e}");
    }
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
    clear_after: Option<u64>,
) -> anyhow::Result<()> {
    {
        let mut state = state.lock().await;
        if let Some(clipboard) = &mut state.clipboard {
            clipboard.set_text(text).map_err(|e| {
                anyhow::anyhow!("couldn't store value to clipboard: {e}")
            })?;
        }
    }

    if let Some(seconds) = clear_after {
        let text = zeroize::Zeroizing::new(text.to_string());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
            let mut state = state.lock().await;
            if let Some(clipboard) = &mut state.clipboard {
                if clipboard.get_text().is_ok_and(|t| *t == **text) {
                    let _ = clipboard.clear();
                }
            }
        });
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
    _clear_after: Option<u64>,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    config.email.map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        Ok,
    )
}

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

// a missing db means we were never logged in. Any other error (a file we
// can't read, invalid json) must not be taken for that: the agent would
// start an interactive login and overwrite the cached vault
async fn load_db_or_new() -> anyhow::Result<rbw::db::Db> {
    match load_db().await {
        Ok(db) => Ok(db),
        Err(e)
            if matches!(
                e.downcast_ref::<rbw::error::Error>(),
                Some(rbw::error::Error::LoadDbAsync { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(rbw::db::Db::new())
        }
        Err(e) => Err(e),
    }
}

async fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn config_base_url() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.base_url())
}

async fn config_persistent_login() -> anyhow::Result<bool> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.persistent_login)
}

async fn config_notify() -> anyhow::Result<bool> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.notify)
}

async fn config_host() -> anyhow::Result<String> {
    let url_str = config_base_url().await?;
    let url =
        reqwest::Url::parse(&url_str).context("failed to parse base url")?;
    url.host_str()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!("couldn't find host in rbw base url {url_str}")
        })
}

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = rbw::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = rbw::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment, None).await?;

    let db = load_db().await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment, None).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db().await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(anyhow::Error::new)?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Matching entry has no private key")
                    })?;

                let private_key_plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    private_key_enc,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;

                return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
                    private_key_plaintext,
                )
                .map_err(anyhow::Error::new);
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}
