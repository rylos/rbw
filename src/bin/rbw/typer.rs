// Typing a value into the window that had the focus before the tui, like
// rofi-rbw does: give the focus back, wait for the keys of the shortcut to be
// released, then type with the first typing tool found.
//
// Giving the focus back needs the compositor: Hyprland (focus history),
// niri (focus-window-previous) and sway (the focus order in its tree).
// Elsewhere (KDE, GNOME...) the tui does what rofi-rbw does: it goes away
// first, its window closes and the desktop gives the focus back by itself,
// then a detached rbw types. That needs the tui to have its own window
// (`konsole -e rbw tui`): started from a shell, the terminal would stay and
// get the value, so typing is refused there.
//
// With hide (after_typing = hide) the tui's window first goes out of sight,
// so that a floating one doesn't cover the window typed into: Hyprland's
// special workspace HIDDEN, sway's scratchpad. The shortcut that opens the
// tui can bring it back. niri has neither, there the tui just stays.

use anyhow::Context as _;
use std::io::Write as _;

// time to let go of Alt before the first key is sent, or the typed letters
// would be read as shortcuts
const START_DELAY: std::time::Duration =
    std::time::Duration::from_millis(400);

pub const HIDDEN: &str = "special:rbw";

// a tab in the text is typed as the Tab key, to go to the next field
pub fn type_into_previous_window(
    text: &str,
    hide: bool,
) -> anyhow::Result<()> {
    if text.contains('\n') {
        return Err(anyhow::anyhow!("multi-line values can't be typed"));
    }
    focus_previous_window(hide)?;
    std::thread::sleep(START_DELAY);
    type_parts(text)
}

fn type_parts(text: &str) -> anyhow::Result<()> {
    for (n, part) in text.split('\t').enumerate() {
        if n > 0 {
            press_tab()?;
        }
        if !part.is_empty() {
            type_text(part)?;
        }
    }
    Ok(())
}

// Hyprland, niri or sway: the focus can be given back with the tui open
pub fn can_give_focus() -> bool {
    ["HYPRLAND_INSTANCE_SIGNATURE", "NIRI_SOCKET", "SWAYSOCK"]
        .iter()
        .any(|v| std::env::var_os(v).is_some())
}

// how long the terminal has to close once the tui quits
const AFTER_EXIT_DELAY: std::time::Duration =
    std::time::Duration::from_millis(500);

// the tui is about to quit: a detached `rbw type-after-exit` gets the value
// on stdin and types it once the tui's window is gone
pub fn type_after_exit(text: &str) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt as _;

    if text.contains('\n') {
        return Err(anyhow::anyhow!("multi-line values can't be typed"));
    }
    if started_from_shell() {
        return Err(anyhow::anyhow!(
            "on this desktop typing needs the tui in its own window (e.g. \
             konsole -e rbw tui): from a shell the value would land in the \
             terminal"
        ));
    }
    let exe = std::env::current_exe().context("failed to find rbw")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("type-after-exit")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // its own session: no hangup when the terminal closes
    // SAFETY: setsid is async-signal-safe and touches no memory
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("failed to run rbw")?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(text.as_bytes())
        .context("failed to send the value")?;
    Ok(())
}

// rbw type-after-exit
pub fn type_after_exit_child() -> anyhow::Result<()> {
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
        .context("failed to read the value")?;
    std::thread::sleep(AFTER_EXIT_DELAY);
    type_parts(&text)
}

// an interactive shell (not `sh -c`) is the tui's parent
fn started_from_shell() -> bool {
    const SHELLS: &[&str] = &[
        "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh",
        "nu", "xonsh", "elvish", "ion", "oil", "osh",
    ];
    let parent = std::os::unix::process::parent_id();
    let comm = std::fs::read_to_string(format!("/proc/{parent}/comm"))
        .unwrap_or_default();
    if !SHELLS.contains(&comm.trim()) {
        return false;
    }
    let cmdline =
        std::fs::read(format!("/proc/{parent}/cmdline")).unwrap_or_default();
    !cmdline.split(|b| *b == 0).any(|arg| arg == b"-c")
}

fn no_window() -> anyhow::Error {
    anyhow::anyhow!("no window to type into (none had the focus before)")
}

fn focus_previous_window(hide: bool) -> anyhow::Result<()> {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some() {
        return hyprland_focus_previous(hide);
    }
    if std::env::var_os("NIRI_SOCKET").is_some() {
        if run_ok("niri", &["msg", "action", "focus-window-previous"]) {
            return Ok(());
        }
        return Err(anyhow::anyhow!("niri couldn't move the focus"));
    }
    if std::env::var_os("SWAYSOCK").is_some() {
        return sway_focus_previous(hide);
    }
    Err(anyhow::anyhow!(
        "typing needs Hyprland, niri or sway, to give the focus back to the \
         previous window"
    ))
}

fn hyprland_focus_previous(hide: bool) -> anyhow::Result<()> {
    let out = std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
        .context("failed to run hyprctl")?;
    let clients: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout)
        .context("failed to read the windows from hyprctl")?;
    let address = |id: u64| {
        clients
            .iter()
            .find(|c| c["focusHistoryID"].as_u64() == Some(id))
            .and_then(|c| c["address"].as_str())
            .map(|a| format!("address:{a}"))
    };
    let previous = address(1).ok_or_else(no_window)?;
    if let Some(own) = address(0).filter(|_| hide) {
        let lua = format!(
            "hl.dsp.window.move({{ workspace = \"{HIDDEN}\", follow = \
             false, window = \"{own}\" }})"
        );
        // not fatal: the value is still typed, under the tui
        let _ = run_ok("hyprctl", &["dispatch", &lua])
            || run_ok(
                "hyprctl",
                &[
                    "dispatch",
                    "movetoworkspacesilent",
                    &format!("{HIDDEN},{own}"),
                ],
            );
    }
    // the lua config of Hyprland has its own dispatcher syntax; the classic
    // one still works on the hyprlang config
    let lua = format!("hl.dsp.focus({{ window = \"{previous}\" }})");
    if !run_ok("hyprctl", &["dispatch", &lua])
        && !run_ok("hyprctl", &["dispatch", "focuswindow", &previous])
    {
        return Err(anyhow::anyhow!("hyprctl couldn't move the focus"));
    }
    Ok(())
}

// sway keeps, for every container, its children in focus order ("focus"):
// going up from the focused window, the first container with another child
// focused before leads to the previous window, down its own focus order
fn sway_focus_previous(hide: bool) -> anyhow::Result<()> {
    let out = std::process::Command::new("swaymsg")
        .args(["-t", "get_tree"])
        .output()
        .context("failed to run swaymsg")?;
    let tree: serde_json::Value = serde_json::from_slice(&out.stdout)
        .context("failed to read the windows from swaymsg")?;
    let (own, previous) = sway_previous(&tree).ok_or_else(no_window)?;
    if hide {
        let _ = run_ok(
            "swaymsg",
            &[&format!("[con_id={own}]"), "move", "scratchpad"],
        );
    }
    if !run_ok("swaymsg", &[&format!("[con_id={previous}]"), "focus"]) {
        return Err(anyhow::anyhow!("swaymsg couldn't move the focus"));
    }
    Ok(())
}

fn children(
    node: &serde_json::Value,
) -> impl Iterator<Item = &serde_json::Value> {
    ["nodes", "floating_nodes"]
        .into_iter()
        .filter_map(|k| node[k].as_array())
        .flatten()
}

// (focused window, previous window) as con ids
fn sway_previous(tree: &serde_json::Value) -> Option<(u64, u64)> {
    fn path<'a>(
        node: &'a serde_json::Value,
        out: &mut Vec<&'a serde_json::Value>,
    ) -> bool {
        out.push(node);
        if node["focused"].as_bool() == Some(true) {
            return true;
        }
        if children(node).any(|c| path(c, out)) {
            return true;
        }
        out.pop();
        false
    }
    let mut nodes = vec![];
    if !path(tree, &mut nodes) {
        return None;
    }
    let own = nodes.last()?["id"].as_u64()?;
    for pair in nodes.windows(2).rev() {
        let (parent, child) = (pair[0], pair[1]);
        if parent["type"] == "output" || parent["type"] == "root" {
            break;
        }
        let child_id = child["id"].as_u64();
        let Some(mut node) = parent["focus"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_u64)
            .find(|id| Some(*id) != child_id)
            .and_then(|id| {
                children(parent).find(|c| c["id"].as_u64() == Some(id))
            })
        else {
            continue;
        };
        // down to a window, the most recently focused at each level
        loop {
            let next = node["focus"]
                .as_array()
                .and_then(|f| f.first())
                .and_then(serde_json::Value::as_u64)
                .and_then(|id| {
                    children(node).find(|c| c["id"].as_u64() == Some(id))
                });
            match next {
                Some(n) => node = n,
                None => return Some((own, node["id"].as_u64()?)),
            }
        }
    }
    None
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

fn press_tab() -> anyhow::Result<()> {
    let (cmd, args): (&str, &[&str]) = if installed("dotool") {
        return run_with_input("dotool", &[], "key tab\n");
    } else if installed("wtype") {
        ("wtype", &["-k", "Tab"])
    } else if installed("ydotool") {
        ("ydotool", &["key", "15:1", "15:0"])
    } else if installed("xdotool") {
        ("xdotool", &["key", "--clearmodifiers", "Tab"])
    } else {
        return Err(anyhow::anyhow!(
            "no typing tool found (dotool, wtype, ydotool or xdotool)"
        ));
    };
    run_with_input(cmd, args, "")
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
    run_with_input(cmd, args, &input)
}

fn run_with_input(
    cmd: &str,
    args: &[&str],
    input: &str,
) -> anyhow::Result<()> {
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
