# rbw (enhanced fork)

This is the `enhanced` branch of [rylos/rbw](https://github.com/rylos/rbw), a
fork of [doy/rbw](https://github.com/doy/rbw) 1.15.0. It adds full write
support, attachments and an optional login that never expires, and merges a
few pending upstream pull requests. Read-only output (`rbw list --raw`,
`rbw get --raw`, ...) is unchanged apart from an extra `attachments` key, so
tools built on it, like [rofi-rbw](https://github.com/fdw/rofi-rbw), keep
working. Tested against Vaultwarden 1.37.4: `tests/vw/e2e.sh` runs every new
command against a throwaway Vaultwarden in docker and checks each write with
an independent decryptor.

### Added

* **Edit every field.** `rbw add` and `rbw edit` set username, password,
  TOTP, URIs, custom fields (text, hidden, boolean), folder and notes. Without
  options they open an editor showing all fields; with options they don't open
  anything (handy for scripts, #220, #365, #35):

  ```sh
  echo "$PW" | rbw add Example me --uri https://example.com --password-stdin \
      --totp otpauth://... --field pin=1234 --hidden-field token=abc --folder Web
  rbw add --secure-note Recipe --notes-file recipe.md
  echo "$NEW" | rbw edit Example --password-stdin   # old password goes to the history
  rbw edit Example --rename Example2 --move-to Archive --add-uri https://b.example
  rbw edit Example --hidden-field token=new --remove-field pin --favorite true
  ```
* **Attachments** (#130): `rbw attachment list|get|add|rm <entry>`. `get`
  saves to the attachment's name (or `-o file`, `-o -` for stdout), `add --file
  f` uploads (`--file - --name n` from stdin), `rbw add --attach f`. Files are
  encrypted in the agent with their own key, like the official clients do.
* **Trash:** `rbw rm` moves the entry to the trash; `rbw trash` lists it,
  `rbw restore <name>` brings it back, `rbw rm --permanent` deletes for good.
* **Folders:** `rbw folder list|add|rename|rm`.
* **Persistent login** (`rbw config set persistent_login true`): when the
  server rejects the refresh token (on Vaultwarden it expires after 30 days
  without a sync, #32), the agent logs in again with your personal API key
  instead of asking for the second factor; `rbw login` uses it too. The key is
  asked for with the pinentry (prompts `API key client__id` and `API key
  client__secret`), so a wrapper can answer from a keyring (examples in
  `contrib/`), and is kept in the agent's memory. Find it in the web vault under
  *Settings → Security → Keys → View API key*. API key logins skip two factor
  authentication.
* **Desktop notification** (`notify-send`, once) when the agent can no longer
  sync because the login expired, instead of failing silently (`rbw config set
  notify false` turns it off).

### Changed

* `rbw edit` fetches the entry from the server, re-encrypts only the values
  that changed and sends everything else back untouched: passkeys,
  attachments, favorites, archive state, per-item keys and item types rbw
  doesn't know about survive an edit. The server's revision check rejects the
  write if the entry changed elsewhere in the meantime. Nothing is written when
  nothing changed (#21).
* `rbw rm` moves to the trash (see above).
* Token refreshes requested by the client go through the agent.
* Entries of types rbw can't display (bank accounts, passports, driver's
  licenses) are listed as notes instead of disappearing.
* The agent protocol is extended, so the fork's `rbw` and `rbw-agent` must be
  used together (`rbw stop-agent` after installing).

### Fixed

* `rbw add` and `rbw edit` failed with 422 on Vaultwarden 1.34+: they now send
  `encryptedFor` and `lastKnownRevisionDate` (#385).
* `rbw edit` corrupted entries with an individual encryption key (#364) and
  dropped their passkeys, reprompt setting and archive state.
* `rbw edit` with a non-tty, empty stdin wiped the password and notes; it now
  refuses (#377).
* Notes lines starting with `#` were dropped when editing; the new editor
  keeps them.
* The agent rewrote its cache in place, so a command reading it at the same
  moment failed with `EOF while parsing`, and the agent itself took the
  half-written file for "not logged in" and asked for the master password
  and the 2FA code again. The cache is now replaced atomically, and only a
  missing file means logged out.
* Commands started together on a stopped or locked agent (a script and
  rofi-rbw, say) each opened their own pinentry, and all but the first
  usually failed with `Connection refused` or stopped the agent the first had
  just started. Now they wait for one agent and one prompt: unlocking,
  logging in and getting a new token happen one at a time.

### Merged upstream pull requests

* #378 persist rotated refresh tokens, stop retrying a rejected one
* #359 batched decryption (`rbw list` and rofi-rbw are much faster on big
  vaults)
* #207 sync and lock timers keep working across system sleep
* #323 `rbw inject` and `rbw run`
* #376, #332, #388 lints and RUSTSEC fixes, no panic on disconnected clients,
  pinentry over ssh

---

This is an unofficial command line client for
[Bitwarden](https://bitwarden.com/). Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Maintenance

I consider `rbw` to be essentially feature-complete for me at this point. While
I still use it on a daily basis, and will continue to fix regressions as they
occur, I am unlikely to spend time implementing new features on my own. If you
would like to see new functionality in `rbw`, I am more than happy to review
and merge pull requests implementing those features.

## Installation

### Arch Linux

`rbw` is available in the [extra
repository](https://archlinux.org/packages/extra/x86_64/rbw/).
Alternatively, you can install
[`rbw-git`](https://aur.archlinux.org/packages/rbw-git/) from the AUR, which
will always build from the latest master commit.

### Debian/Ubuntu

`rbw` is officially packaged for Debian as
[`rust-rbw`](https://tracker.debian.org/pkg/rust-rbw) and is available in
testing (forky). You can install it using `sudo apt install rbw`.

Alternatively, you can download a Debian package from
[https://git.tozt.net/rbw/releases/deb/
](https://git.tozt.net/rbw/releases/deb/). The packages are signed by
[`minisign`](https://github.com/jedisct1/minisign), and can be verified using
the public key `RWTM0AZ5RpROOfAIWx1HvYQ6pw1+FKwN6526UFTKNImP/Hz3ynCFst3r`.

### Fedora/EPEL

`rbw` is available in [Fedora and EPEL 9](https://bodhi.fedoraproject.org/updates/?packages=rust-rbw)
(for RHEL and compatible distributions).

You can install it using `sudo dnf install rbw`.

### Homebrew

`rbw` is available in the [Homebrew repository](https://formulae.brew.sh/formula/rbw). You can install it via `brew install rbw`.

### Nix

`rbw` is available in the
[NixOS repository](https://search.nixos.org/packages?show=rbw). You can try
it out via `nix-shell -p rbw`.

### Alpine

`rbw` is available in the [community repository](https://pkgs.alpinelinux.org/packages?name=rbw). You can install it with `apk add rbw`.

### Other

With a working Rust installation, `rbw` can be installed via `cargo install
--locked rbw`. This requires that the
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program is installed (to display password prompts).

## Configuration

Configuration options are set using the `rbw config` command. Available
configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `sso_id`: The SSO organization ID. Defaults to regular login process if unset.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `ui_url`: The URL of the Bitwarden UI to use. If unset,
  will default to `https://vault.bitwarden.com/`.
* `notifications_url`: The URL of the Bitwarden notifications server to use.
  If unset, will use the `/notifications` path on the configured `base_url`,
  or `https://notifications.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: The number of seconds to keep the master keys in memory for
  before requiring the password to be entered again. Defaults to `3600` (one
  hour).
* `sync_interval`: `rbw` will automatically sync the database from the server
  at an interval of this many seconds, while the agent is running. Setting
  this value to `0` disables this behavior. Defaults to `3600` (one hour).
* `pinentry`: The
  [pinentry](https://www.gnupg.org/related_software/pinentry/index.html)
  executable to use. Defaults to `pinentry`.

### Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.

## Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will run `rbw unlock` to
unlock the password database before generating the list of entries (but will
not attempt to log in to the server), `rbw sync` will automatically run `rbw
login` to log in to the server before downloading the password database (but
will not unlock the database), and `rbw add` will do both.

Logging into the server and unlocking the database will only be done as
necessary, so running `rbw login` when you are already logged in will do
nothing, and similarly for `rbw unlock`. If necessary, you can explicitly log
out by running `rbw purge`, and you can explicitly lock the database by running
`rbw lock` or `rbw stop-agent`.

`rbw help` can be used to get more information about the available
functionality.

Run `rbw get <name>` to get your passwords. If you also want to get the username
or the note associated, you can use the flag `--full`. You can also use the flag
`--field={field}` to get whatever default or custom field you want. The `--raw`
flag will show the output as JSON. In addition to matching against the name,
you can pass a UUID as the name to search for the entry with that id, or a
URL to search for an entry with a matching website entry.

### Template and command injection

`rbw inject` can render templates containing secret references. References use
the format `bw://<uuid-or-name>?field=<field>`, where the item can be addressed
by UUID or by an exact name consisting only of letters, digits, `-`, and `_`.
For items whose names contain spaces or other punctuation, use the item UUID
instead. If `field` is omitted, the entry password is used. References can be
written directly in the template or wrapped in `{{ bw://... }}`.

By default, `rbw inject` reads the template from stdin and writes the rendered
output to stdout. Use `--in-file` and `--out-file` to work with files instead:

```sh
echo 'database_password={{ bw://db-prod?field=password }}' | rbw inject
rbw inject --in-file config.tpl --out-file config.yaml
```

`rbw run` reads environment bindings from `./.env` by default (or another file
with `--env-file`), parses them using dotenv syntax, resolves any `bw://`
references in the resulting values, and then runs the requested command without
going through a shell:

```sh
cat > .env <<'EOF'
DATABASE_URL=postgres://app:bw://db-prod?field=password@db.example/app
API_TOKEN=bw://deploy-token
EOF

rbw run -- env
rbw run --env-file .env.local -- docker compose up -d
```

*Note to users of the official Bitwarden server (at bitwarden.com)*: The
official server has a tendency to detect command line traffic as bot traffic
(see [this issue](https://github.com/bitwarden/cli/issues/383) for details). In
order to use `rbw` with the official Bitwarden server, you will need to first
run `rbw register` to register each device using `rbw` with the Bitwarden
server. This will prompt you for your personal API key which you can find using
the instructions [here](https://bitwarden.com/help/article/personal-api-key/).

### SSH Agent

`rbw-agent` includes a built-in SSH agent for signing SSH authentication
challenges directly. To use it, ensure that rbw is running (in order to make
it start handling ssh agent requests), and then point your SSH client to the
SSH agent socket:

```sh
rbw unlock
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent-socket"
```

If you're using a profile, the socket will be located at
`"XDG_RUNTIME_DIR/rbw-<profile>/ssh-agent-socket"`.

### 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)

WebAuthn / Passkey and Duo security are unsupported 2FA mechanisms.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Related projects

* [rofi-rbw](https://github.com/fdw/rofi-rbw): A rofi frontend for Bitwarden
* [bw-ssh](https://framagit.org/Glandos/bw-ssh/): Manage SSH key passphrases in Bitwarden
* [rbw-menu](https://github.com/rbuchberger/rbw-menu): Tiny menu picker for rbw
* [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw): [Ulauncher](https://ulauncher.io/) rbw extension
* [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw): A fuzzel frontend for Bitwarden
