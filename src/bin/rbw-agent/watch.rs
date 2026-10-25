// lock_on_sleep and lock_on_idle.
//
// Sleep is noticed on wakeup: CLOCK_BOOTTIME keeps counting while the system
// is suspended and CLOCK_MONOTONIC doesn't, so a jump in their difference
// means the system slept. That needs no dbus connection, and the keys were
// in memory during the sleep either way.
//
// Idle is logind's IdleHint or LockedHint for the agent's session (set by
// most idle daemons and screen lockers); the agent locks when either turns
// on, not while it stays on, so unlocking from a locked screen still works.

const TICK: std::time::Duration = std::time::Duration::from_secs(5);
const IDLE_EVERY: u32 = 3;

fn clock(id: libc::clockid_t) -> std::time::Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // safe: clock_gettime only writes to the timespec we pass
    unsafe { libc::clock_gettime(id, &raw mut ts) };
    std::time::Duration::new(
        u64::try_from(ts.tv_sec).unwrap_or(0),
        u32::try_from(ts.tv_nsec).unwrap_or(0),
    )
}

fn suspended_time() -> std::time::Duration {
    clock(libc::CLOCK_BOOTTIME).saturating_sub(clock(libc::CLOCK_MONOTONIC))
}

async fn session_idle() -> Option<bool> {
    let out = tokio::process::Command::new("loginctl")
        .args(["show-session", "auto", "-p", "IdleHint", "-p", "LockedHint"])
        .arg("--value")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l == "yes"),
    )
}

pub async fn run(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) {
    let mut suspended = suspended_time();
    let mut was_idle = false;
    let mut tick = 0_u32;
    loop {
        tokio::time::sleep(TICK).await;
        tick = tick.wrapping_add(1);
        let settings = state.lock().await.settings;

        let now_suspended = suspended_time();
        if settings.lock_on_sleep
            && now_suspended.saturating_sub(suspended)
                > std::time::Duration::from_secs(1)
        {
            log::info!("the system slept, locking");
            state.lock().await.clear();
        }
        suspended = now_suspended;

        if settings.lock_on_idle && tick % IDLE_EVERY == 0 {
            if let Some(idle) = session_idle().await {
                if idle && !was_idle {
                    log::info!("the session went idle, locking");
                    state.lock().await.clear();
                }
                was_idle = idle;
            }
        }
    }
}
