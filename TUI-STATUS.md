# `tui` branch: status

Work in progress on top of `enhanced` (which stays the stable, public
branch). Goal: replace the official desktop client with a fast TUI, biometric
unlock (polkit + howdy/fprintd, also for the first unlock) and, separately, a
Noctalia bar plugin. A browser extension talking to the agent comes last, if
at all.

## Done

### Phase 1: agent (protocol 2, `rbw stop-agent` after installing)
- `rbw biometric enroll|disable|status`, config `biometric`,
  `biometric_store` (`src/biometric.rs`, `contrib/polkit/`).
  - unlock asks polkit for `net.rbw.unlock` (`pkcheck`, subject = the client
    process from SO_PEERCRED, the agent itself for ssh-agent requests);
    refused or unavailable → pinentry as before.
  - lock with biometric keeps the keys (`soft_locked`), `State::key()` returns
    nothing while locked; `rbw lock --hard`, logout and disable drop them.
  - first unlock: master password saved with `systemd-creds --user
    --with-key=auto` (TPM2 + host key, host key without a TPM) or the Secret
    Service (`secret-tool`, item `service rbw account rbw-biometric`).
- `rbw status [--json]`: never starts the agent or prompts (for bars).
- usage ranking (`src/usage.rs`, ids only, half-life 14 days): `get` and
  `code` record, `sort_by_usage` sorts `list`/`search`.
- e2e: 70/70 (`tests/vw/e2e.sh`, polkit faked with a fake `pkcheck`).

## Machine setup done (pc-casa, 2026-10-25)
- `/usr/share/polkit-1/actions/net.rbw.unlock.policy`
- `/etc/pam.d/polkit-1` = contrib/polkit/polkit-1.pam (howdy on top;
  remove the file to go back to `/usr/lib/pam.d/polkit-1`)
- `/etc/systemd/system/polkit-agent-helper@.service.d/biometric.conf`:
  without it the sandboxed helper can't open the camera. Verified: `pkcheck`
  → howdy "Login approved" in 1.3 s.
- pc-work: none of this yet (needs the same three files; check which camera
  howdy uses there).

## Next
- Phase 2: `rbw tui` (ratatui + nucleo), see plan below.
- Phase 3: Noctalia plugin in rylos/community-plugins (separate project, only
  uses `rbw status --json` and plain `rbw` commands).
- Phase 4 (maybe): browser extension via native messaging.

## TUI plan
- subcommand of the `rbw` binary (reuses the client's decrypt and edit code).
- one `DecryptMany` round trip for name/user/folder/uris, fuzzy filter in
  memory, sorted by usage then name; secrets decrypted only on demand.
- keys: type to filter, ↑/↓, Enter copy password, `u` user, `t` TOTP,
  `o` open URI, `e` edit ($EDITOR form), `n` new, `d` trash, `s` sync,
  `l` lock, `?` help, Esc/Ctrl-C quit; clipboard cleared after 30 s.
