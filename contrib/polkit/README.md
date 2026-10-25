# Biometric unlock

`rbw config set system_auth true` makes the agent unlock through polkit
instead of asking for the master password: polkit runs its `polkit-1` PAM stack as root, so face (howdy) or
fingerprint (fprintd) modules work, and your desktop's polkit agent shows the
dialog. Cancelling it falls back to the master password.

1. Install the action (root):

       install -Dm644 net.rbw.unlock.policy /usr/share/polkit-1/actions/net.rbw.unlock.policy

2. Add your biometric module to the polkit stack, if it isn't there already.
   Most distributions leave `polkit-1` on plain password authentication, which
   is also why the official desktop client's biometric unlock ignores howdy.
   `polkit-1.pam` is an example for Arch; start from your distribution's file.

3. polkit 127 and newer run the authentication in the sandboxed
   `polkit-agent-helper@.service`, which can't see any device, so howdy fails
   with "not possible to open camera" and polkit asks for the password. Let it
   through (this is also what breaks the official client's biometric unlock):

       install -Dm644 polkit-agent-helper-biometric.conf \
           /etc/systemd/system/polkit-agent-helper@.service.d/biometric.conf
       systemctl daemon-reload

4. Make sure a polkit agent runs in your session (Plasma, GNOME do; on
   Hyprland or niri use e.g. `hyprpolkitagent` or `polkit-kde-agent`).

5. `rbw config set system_auth true`. Unlocking now reuses the keys the agent
   kept when it locked (with `timeout_action lock`, the default). For the
   first unlock after the agent starts as well, `rbw remember-password` asks
   for the master password once and saves it with `systemd-creds` (user
   scoped, tied to this machine: TPM2 + host key when there is a TPM, host key
   otherwise), or with `--store secret-service` in the keyring. Without it,
   that first unlock asks for the master password, like the official clients'
   "require the master password on restart".

`rbw security` shows all the lock and unlock settings and what this machine
supports; `rbw tui` has them under F2. A pin (`rbw pin set`) works the same
way, without polkit.

Security: any program running as you can read the saved password back, just
like a password a pinentry wrapper reads from the keyring. A pin or
biometrics protect against someone at the keyboard, not against malware
running as you.
