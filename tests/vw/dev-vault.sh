#!/bin/bash
# A throwaway Vaultwarden with a few entries, for trying the debug build by
# hand (e.g. `rbw tui`) without touching the real vault:
#
#   tests/vw/dev-vault.sh          # start and fill it
#   PATH=target/debug:$PATH RBW_PROFILE=rbwdev rbw tui
#   tests/vw/dev-vault.sh stop
#
# Same container setup as e2e.sh, on port 8223 so both can run.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
URL=http://127.0.0.1:8223
EMAIL=dev@rbw.local
PW=test-password-123
export RBW_PROFILE=rbwdev RBW_TEST_PIN=$PW
export PATH="$ROOT/target/debug:$PATH"

if [ "${1:-}" = stop ]; then
    rbw stop-agent 2>/dev/null || true
    docker rm -f vw-dev >/dev/null 2>&1 || true
    exit 0
fi

(cd "$ROOT" && cargo build -q)
docker rm -f vw-dev >/dev/null 2>&1 || true
docker run -d --name vw-dev --network host \
    -e ROCKET_ADDRESS=127.0.0.1 -e ROCKET_PORT=8223 \
    -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    "vaultwarden/server:${TAG:-1.37.4}" >/dev/null
until curl -sf "$URL/alive" >/dev/null; do sleep 0.5; done
python3 -I "$ROOT/tests/vw/register.py" "$URL" "$EMAIL" "$PW" >/dev/null

rbw stop-agent 2>/dev/null || true
rm -rf "$HOME/.cache/rbw-rbwdev" "$HOME/.config/rbw-rbwdev" "$HOME/.local/share/rbw-rbwdev"
rbw config set email "$EMAIL"
rbw config set base_url "$URL"
rbw config set pinentry "$ROOT/tests/vw/pinentry-test"
rbw login

add() { echo "$3" | rbw add "$1" "$2" --password-stdin "${@:4}"; }
add GitHub marco gh-pass-1 --uri https://github.com/login --totp JBSWY3DPEHPK3PXP --folder Dev
add GitLab marco gl-pass --uri https://gitlab.com --folder Dev
add "Home Assistant" admin ha-pass --uri http://nas.lan:8123 --folder Casa
add Proxmox root pve-pass --uri https://srv09.ts:8006 --folder Lavoro --hidden-field "api token=PVEAPI=abc"
add Amazon marco@example.com amz-pass --uri https://www.amazon.it --folder Shopping
add "Banca Intesa" 12345678 bank-pass --uri https://www.intesasanpaolo.com --field pin=4321
add Router root fw-pass --uri https://192.168.1.254 --folder Casa
for i in $(seq 1 40); do
    add "Service $i" "user$i" "pw-$i" --uri "https://s$i.example.com" --folder Varie
done
rbw add "Wi-Fi casa" --secure-note --notes $'SSID: casa\nPassword: wifi-pass'
rbw sync
echo "ready: PATH=$ROOT/target/debug:\$PATH RBW_PROFILE=rbwdev rbw tui"
