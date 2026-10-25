// Typing a value into the window that had the focus before the tui, like
// rofi-rbw does: give the focus back, wait for the keys of the shortcut to be
// released, then type with the first typing tool found.
//
// Giving the focus back needs the compositor: Hyprland (focus history) and
// niri (focus-window-previous). Elsewhere the value would land in the tui's
// own terminal, so typing is refused.

use anyhow::Context as _;
use std::io::Write as _;

// time to let go of Alt before the first key is sent, or the typed letters
// would be read as shortcuts
const START_DELAY: std::time::Duration =
    std::time::Duration::from_millis(400);

pub fn type_into_previous_window(text: &str) -> anyhow::Result<()> {
    if text.contains('\n') {
        return Err(anyhow::anyhow!("multi-line values can't be typed"));
    }
    focus_previous_window()?;
    std::thread::sleep(START_DELAY);
    type_text(text)
}

fn focus_previous_window() -> anyhow::Result<()> {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some() {
        let out = std::process::Command::new("hyprctl")
            .args(["clients", "-j"])
            .output()
            .context("failed to run hyprctl")?;
        let clients: Vec<serde_json::Value> =
            serde_json::from_slice(&out.stdout)
                .context("failed to read the windows from hyprctl")?;
        let previous = clients
            .iter()
            .find(|c| c["focusHistoryID"].as_u64() == Some(1))
            .and_then(|c| c["address"].as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no window to type into (none had the focus before)"
                )
            })?;
        let target = format!("address:{previous}");
        // the lua config of Hyprland has its own dispatcher syntax; the
        // classic one still works on the hyprlang config
        let lua = format!("hl.dsp.focus({{ window = \"{target}\" }})");
        if !run_ok("hyprctl", &["dispatch", &lua])
            && !run_ok("hyprctl", &["dispatch", "focuswindow", &target])
        {
            return Err(anyhow::anyhow!("hyprctl couldn't move the focus"));
        }
        return Ok(());
    }
    if std::env::var_os("NIRI_SOCKET").is_some() {
        if run_ok("niri", &["msg", "action", "focus-window-previous"]) {
            return Ok(());
        }
        return Err(anyhow::anyhow!("niri couldn't move the focus"));
    }
    Err(anyhow::anyhow!(
        "typing needs Hyprland or niri, to give the focus back to the \
         previous window"
    ))
}

// hyprctl answers "ok" on success, and an error text with exit code 0
fn run_ok(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .is_ok_and(|out| {
            out.status.success()
                && !String::from_utf8_lossy(&out.stdout)
                    .to_lowercase()
                    .contains("error")
                && !String::from_utf8_lossy(&out.stdout)
                    .to_lowercase()
                    .contains("invalid")
        })
}

fn installed(cmd: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join(cmd).is_file())
    })
}

// the value goes through stdin, never the command line, where other users
// could read it in /proc
fn type_text(text: &str) -> anyhow::Result<()> {
    let (cmd, args, input): (&str, &[&str], String) = if installed("dotool") {
        ("dotool", &[], format!("type {text}\n"))
    } else if installed("wtype") {
        ("wtype", &["-"], text.to_string())
    } else if installed("ydotool") {
        ("ydotool", &["type", "--file", "-"], text.to_string())
    } else if installed("xdotool") {
        (
            "xdotool",
            &["type", "--clearmodifiers", "--file", "-"],
            text.to_string(),
        )
    } else {
        return Err(anyhow::anyhow!(
            "no typing tool found (dotool, wtype, ydotool or xdotool)"
        ));
    };
    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {cmd}"))?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(input.as_bytes())
        .with_context(|| format!("failed to send the text to {cmd}"))?;
    let out = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for {cmd}"))?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
