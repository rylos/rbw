# `tui` branch: status

Work in progress on top of `enhanced` (which stays the stable, public
branch: don't merge until this is finished and tested on the real vault).
Goal: replace the official desktop client with a fast TUI, unlock options
like the official clients (pin, system authentication with howdy/fprintd,
also after a restart) and, as a separate project, a Noctalia bar plugin. A
browser extension talking to the agent comes last, if at all.

Constraint: rofi-rbw must keep working exactly as today (`list --raw`,
`get --raw`, `code`, `sync` unchanged; e2e section "rofi-rbw" runs its real
code).

## Done

### Agent (protocol 2: `rbw stop-agent` after installing)
Lock and unlock settings, mirroring the official "Security" page:

| official | rbw |
|---|---|
| session timeout 1 min … 4 h, custom | `lock_timeout 1h`, `90m`, seconds |
| on restart / never | `lock_timeout never` (0) |
| when the system is idle | `lock_on_idle` (logind IdleHint/LockedHint, `watch.rs`) |
| when the system sleeps | `lock_on_sleep` (BOOTTIME − MONOTONIC jump) |
| timeout action lock / log out | `timeout_action lock` / `forget` |
| unlock with PIN | `rbw pin set` / `rbw pin clear` (`src/pin.rs`, argon2id, 5 tries) |
| unlock with system authentication | `system_auth` (polkit `net.rbw.unlock`) |
| require master password on restart | unchecked = `rbw remember-password` |

- unlock order: system (polkit) → pin → master password; the first two
  only when there is something to reuse (kept keys or saved password).
- `timeout_action lock` with pin or system auth keeps the keys
  (`soft_locked`, `State::key()` returns nothing); otherwise, and with
  `lock --hard`, logout, `forget`, the keys are dropped.
- saved master password: `systemd-creds --user --with-key=auto` (TPM2 +
  host key; host key without TPM) or Secret Service (`service rbw account
  rbw-biometric`), `src/biometric.rs`.
- lock settings are applied live (`ReloadConfig`), the agent isn't
  restarted; config saved atomically.
- `rbw security` overview, `rbw status [--json]` (never starts the agent or
  prompts: for bars).
- usage ranking (`src/usage.rs`, ids only): `get`/`code` record,
  `sort_by_usage` sorts `list`/`search`, the tui always uses it.

### TUI (`rbw tui`, `src/bin/rbw/tui.rs`, `settings.rs`)
- fuzzy filter (nucleo), usage first; Enter copies, Tab picks a field,
  ^U ^T ^R ^O ^E ^N ^D ^S ^L, F1 help, F2 security settings.
- clipboard cleared by the agent after 30 s; details dropped as soon as
  the agent locks, unlock again before the next key needing a secret.
- startup ≈ `rbw list` (≈ 40 ms on the real 1681-entry vault).

### Tests
- `bash tests/vw/e2e.sh`: 93/93 (polkit faked; tui driven with tmux).
- `tests/vw/dev-vault.sh`: throwaway vault on :8223 for trying the tui
  (`PATH=target/debug:$PATH RBW_PROFILE=rbwdev rbw tui`).
- Real polkit + howdy tested on pc-casa with the dev vault: first unlock
  (saved password, TPM2) 3.7 s in a debug build, re-unlock 1.2 s.

### Noctalia plugin (separate project)
- `rylos/community-plugins`, branch `rbw`, directory `rbw/` (id `rylos/rbw`,
  plugin_api 34 = Noctalia 5.3.0): service polling `rbw status --json`, bar
  widget (lock glyph, right click lock/unlock), panel (open `rbw tui`,
  unlock/lock, sync, `rbw tui --settings`, log in). README follows
  README_TEMPLATE.md, only `translations/en.json` (repo rule). CI validator
  passes except the missing `thumbnail.webp` (must be made with the
  thumbnail generator from a screenshot).
- Tested live on pc-casa against the dev vault: panel, unlock, sync, tui in
  a terminal, bar glyph locked/unlocked.

## Machine setup done (pc-casa, 2026-10-25)
- `/usr/share/polkit-1/actions/net.rbw.unlock.policy`
- `/etc/pam.d/polkit-1` = contrib/polkit/polkit-1.pam (howdy on top;
  remove the file to go back to `/usr/lib/pam.d/polkit-1`)
- `/etc/systemd/system/polkit-agent-helper@.service.d/biometric.conf`:
  without it the sandboxed helper can't open the camera ("not possible to
  open camera"), which is also why the official client's system unlock
  never used howdy.
- pc-work: none of this yet (same three files; check howdy's camera there).
- The real vault still runs the `enhanced` package (rbw-enhanced): nothing
  of this branch is installed.
- Noctalia: plugin copied to `~/.local/share/noctalia/plugins/rbw/`, enabled,
  widget `rbw` added to the default bar after `bar_2`
  (`~/.local/state/noctalia/settings.toml`, backup
  `settings.toml.bak-20261025-rbw`). TEMPORARY: `[plugin_settings."rylos/rbw"]
  rbw_bin` points to a wrapper in the session scratchpad (debug build,
  `RBW_PROFILE=rbwdev`); remove it once this branch is installed, or the
  widget shows an error after a reboot.

## Next
1. Try it on the real vault: build a package from this branch, `rbw
   stop-agent`, check rofi-rbw, then pick the settings (F2).
2. Noctalia plugin: make `thumbnail.webp` with the generator, then a PR to
   noctalia-dev/community-plugins (PR template: tested compositors, version,
   accounting of every spawned process). Only after this branch is
   released, since the plugin needs `rbw status --json`.
3. README of the fork: document the new commands when merging.
4. Maybe: browser extension via native messaging to the agent.
