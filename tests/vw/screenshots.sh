#!/bin/bash
# The README screenshots: a throwaway Vaultwarden on port 8224 with neutral
# sample data, `rbw tui` in a foot window, grim for the capture.
#
#   tests/vw/screenshots.sh        # needs docker, foot, grim and Hyprland
#
# Writes docs/screenshots/*.png. Nothing touches the real profile.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
URL=http://127.0.0.1:8224
EMAIL=demo@example.com
PW=test-password-123
OUT=$ROOT/docs/screenshots
export RBW_PROFILE=rbwshot RBW_TEST_PIN=$PW
export PATH="$ROOT/target/debug:$PATH"
WORK=$(mktemp -d)
trap 'rbw stop-agent 2>/dev/null || true; docker rm -f vw-shot >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

(cd "$ROOT" && cargo build -q)
docker rm -f vw-shot >/dev/null 2>&1 || true
docker run -d --name vw-shot --network host \
    -e ROCKET_ADDRESS=127.0.0.1 -e ROCKET_PORT=8224 \
    -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    "vaultwarden/server:${TAG:-1.37.4}" >/dev/null
until curl -sf "$URL/alive" >/dev/null; do sleep 0.5; done
python3 -I "$ROOT/tests/vw/register.py" "$URL" "$EMAIL" "$PW" >/dev/null
bw() { python3 -I "$ROOT/tests/vw/bwtool.py" "$URL" "$EMAIL" "$PW" "$@"; }

rbw stop-agent 2>/dev/null || true
rm -rf "$HOME/.cache/rbw-rbwshot" "$HOME/.config/rbw-rbwshot" "$HOME/.local/share/rbw-rbwshot"
rbw config set email "$EMAIL"
rbw config set base_url "$URL"
rbw config set pinentry "$ROOT/tests/vw/pinentry-test"
rbw login
bw mkorg "Acme Corp" Engineering Finance Marketing >/dev/null
rbw sync

add() { echo "$3" | rbw add "$1" "$2" --password-stdin "${@:4}"; }
add GitHub alice 'k7#Lq2!vRz9pWm' --uri https://github.com/login --totp JBSWY3DPEHPK3PXP --folder Development
add GitLab alice 'Qe4$Tn8wYx1@bc' --uri https://gitlab.com --folder Development
add Mastodon '@alice@example.social' 'Hn5^Kp2#Vm8!Lz' --uri https://example.social --folder Social
add Proton alice@example.com 'Rt9!Ws3@Xk6#Pq' --uri https://account.proton.me --folder Email
add Fastmail alice@example.net 'Mb2#Zc7!Nf4$Ql' --uri https://www.fastmail.com --folder Email
add Amazon alice@example.com 'Yd8@Jh3!Tg6#Wr' --uri https://www.amazon.com --folder Shopping
add eBay alice_buys 'Lp5!Qs9@Bv2#Xm' --uri https://www.ebay.com --folder Shopping
add Netflix alice@example.com 'Fk3#Rw8!Hn5@Zt' --uri https://www.netflix.com --folder Streaming
add Spotify alice 'Vc6@Ny2!Kq9#Ps' --uri https://open.spotify.com --folder Streaming
add 'Home router' admin 'Gx4!Mt7@Wb1#Lr' --uri https://192.0.2.1 --folder Home
add 'Cloud server' root 'Sz8#Pd3!Qh6@Vn' --uri https://203.0.113.10:8006 --folder Home --hidden-field 'api token=PVEAPI=demo'
rbw add 'Wi-Fi' --secure-note --notes $'SSID: home\nPassword: correct-horse-battery' --folder Home
for svc in Jira Confluence Slack Figma Notion; do
    add "$svc" alice 'Tq7!Xr2@Mv5#Kd' --uri "https://$(echo "$svc" | tr A-Z a-z).example.com" --org 'Acme Corp' --collection Engineering
done
add 'Bank portal' acme-finance 'Wn3#Bz8!Pc5@Hl' --uri https://bank.example.com --org 'Acme Corp' --collection Finance
cat >"$WORK/card" <<'EOF'
#!/bin/sh
sed -i 's/^cardholder: .*/cardholder: Alice Doe/; s/^brand: .*/brand: Visa/; s/^number: .*/number: 4111111111111111/; s/^exp month: .*/exp month: 08/; s/^exp year: .*/exp year: 2029/; s/^code: .*/code: 123/' "$1"
EOF
chmod +x "$WORK/card"
VISUAL=$WORK/card script -qec "rbw add 'Visa card' --type card --folder Finance" /dev/null >/dev/null
rbw add 'Deploy key' --type ssh-key --no-edit --folder Development
for fav in GitHub Mastodon Proton; do rbw edit "$fav" --favorite true; done
# a little usage history, so the most used entries come first
for _ in 1 2 3 4 5; do rbw get GitHub >/dev/null; done
for _ in 1 2 3; do rbw get Proton >/dev/null; done
rbw get Netflix >/dev/null
rbw sync

mkdir -p "$OUT"
shot() {
    local name=$1
    local geometry
    geometry=$(hyprctl clients -j | jq -r '.[] | select(.class == "rbw-tui") | "\(.at[0]),\(.at[1]) \(.size[0])x\(.size[1])"' | head -1)
    grim -g "$geometry" "$OUT/$name.png"
}
keys() { for k in "$@"; do wtype -k "$k"; sleep 0.25; done; }
type_text() { wtype "$1"; sleep 0.5; }

# opaque, so the desktop behind doesn't show through
foot --app-id rbw-tui -o colors-dark.alpha=1.0 env PATH="$PATH" RBW_PROFILE=rbwshot RBW_TEST_PIN="$PW" rbw tui &
sleep 2
shot main
type_text gith
keys Tab
wtype -M ctrl r -m ctrl; sleep 0.5
shot details
keys Escape Escape
sleep 0.3
keys Return
sleep 0.5
shot actions
keys Escape
type_text new
wtype -M ctrl n -m ctrl; sleep 0.5
keys Right Down Right
sleep 0.3
shot new-item
keys Escape
wtype -M ctrl w -m ctrl; sleep 0.2
keys F2
sleep 0.5
shot settings
keys Escape
wtype -M ctrl c -m ctrl
sleep 0.5
echo "screenshots in $OUT"
