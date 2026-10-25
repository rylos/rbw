#!/bin/bash
# End-to-end test of the enhanced commands against a throwaway Vaultwarden.
#
#   tests/vw/e2e.sh [vaultwarden image tag]
#
# Starts vaultwarden/server:<tag> (default 1.37.4) on 127.0.0.1:8222 with
# volatile storage, registers a test account, and drives the debug build of
# rbw under RBW_PROFILE=rbwtest. Every write is checked with tests/vw/bwtool.py,
# an independent decryptor, so that the result is what the official clients
# would read. Nothing touches the real profile.
set -euo pipefail

TAG=${1:-1.37.4}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
URL=http://127.0.0.1:8222
EMAIL=test@rbw.local
PW=test-password-123
WORK=$(mktemp -d)
trap 'RBW_PROFILE=rbwtest "$ROOT/target/debug/rbw" stop-agent 2>/dev/null || true; docker rm -f vw-test >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

export RBW_PROFILE=rbwtest
export PATH="$WORK/bin:$ROOT/target/debug:$PATH"
export RBW_TEST_PIN=$PW

pass=0
fail=0
check() {
    local desc=$1 expected=$2 actual=$3
    if [ "$expected" = "$actual" ]; then
        pass=$((pass + 1))
        echo "ok   $desc"
    else
        fail=$((fail + 1))
        echo "FAIL $desc"
        echo "     expected: $expected"
        echo "     actual:   $actual"
    fi
}
bw() { python3 -I "$ROOT/tests/vw/bwtool.py" "$URL" "$EMAIL" "$PW" "$@"; }
item() { bw dump | jq -c --arg n "$1" ".[] | select(.name == \$n) | $2"; }
db() { printf '%s\n' "$HOME/.cache/rbw-rbwtest/"*.json; }
setdb() { local f; f=$(db); jq "$1" "$f" >"$f.tmp" && mv "$f.tmp" "$f"; }

mkdir -p "$WORK/bin"
printf '#!/bin/sh\necho "$*" >> %s/notify.log\n' "$WORK" >"$WORK/bin/notify-send"
chmod +x "$WORK/bin/notify-send"

(cd "$ROOT" && cargo build -q)
docker rm -f vw-test >/dev/null 2>&1 || true
# host networking: no port mapping, so no iptables DNAT rule, which docker
# can't add after a kernel update until the next reboot
docker run -d --name vw-test --network host \
    -e ROCKET_ADDRESS=127.0.0.1 -e ROCKET_PORT=8222 \
    -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
    "vaultwarden/server:$TAG" >/dev/null
until curl -sf "$URL/alive" >/dev/null; do sleep 0.5; done
python3 -I "$ROOT/tests/vw/register.py" "$URL" "$EMAIL" "$PW" >/dev/null

rbw stop-agent
rm -rf "$HOME/.cache/rbw-rbwtest" "$HOME/.config/rbw-rbwtest"
rbw config set email "$EMAIL"
rbw config set base_url "$URL"
rbw config set pinentry "$ROOT/tests/vw/pinentry-test"
rbw login
rbw sync

echo "== add"
printf 'pw-legacy\nnota legacy\n' | rbw add legacy user1 --uri https://legacy.example
check "add from stdin (first line password)" '{"username":"user1","password":"pw-legacy","totp":null,"uris":["https://legacy.example"],"uri_checksums_ok":true,"passkeys":0}' "$(item legacy .login)"
echo pw-flags | rbw add flags --password-stdin --username u2 --totp JBSWY3DPEHPK3PXP \
    --field pin=1234 --hidden-field token=a=b --notes "nota flags" --folder Prove
check "add with flags" '[[0,"pin","1234"],[1,"token","a=b"]]' "$(item flags .fields)"
check "add into a new folder" Prove "$(rbw get --raw flags | jq -r .folder)"
rbw add nota --secure-note --notes "testo nota"
check "add secure note" '2' "$(item nota .type)"
rbw generate 20 generated --no-symbols >/dev/null
check "generate saves the entry" 20 "$(rbw get generated | tr -d '\n' | wc -c)"

echo "== edit"
echo pw-new | rbw edit legacy --password-stdin --rename legacy2 --add-uri https://two.example --move-to Prove
check "edit password keeps history" '["pw-legacy"]' "$(item legacy2 .history)"
check "edit adds uri" '["https://legacy.example","https://two.example"]' "$(item legacy2 .login.uris)"
rbw edit legacy2 --set-uri https://only.example --username '' --favorite true
check "edit replaces uris, clears username" '{"username":null,"uris":["https://only.example"]}' "$(item legacy2 '.login | {username, uris}')"
check "edit sets favorite" true "$(item legacy2 .favorite)"
check "empty stdin doesn't wipe the entry" 1 "$(rbw edit legacy2 </dev/null >/dev/null 2>&1; echo $?)"
check "login values refused on notes" 1 "$(rbw edit nota --totp x >/dev/null 2>&1; echo $?)"

cat >"$WORK/editor" <<'EOF'
#!/bin/sh
sed -i 's/^password: .*/password:  spaced /; s/^folder: .*/folder: Altro/' "$1"
sed -i 's/^--- notes ---$/boolean: on = true\n--- notes ---/' "$1"
printf '# heading kept\nline two\n' >>"$1"
EOF
chmod +x "$WORK/editor"
VISUAL=$WORK/editor script -qec "rbw edit legacy2" /dev/null >/dev/null
check "editor: password with spaces" '" spaced "' "$(item legacy2 .login.password)"
check "editor: notes keep '#' lines" '"nota legacy\n# heading kept\nline two"' "$(item legacy2 .notes)"
check "editor: boolean field" '[[2,"on","true"]]' "$(item legacy2 .fields)"
check "editor: move to new folder" Altro "$(rbw get --raw legacy2 | jq -r .folder)"

echo "== item key, passkey"
bw mkkeyed keyed >/dev/null
rbw sync
echo pw-k | rbw edit keyed --password-stdin --hidden-field new=v --notes changed
check "keyed entry still decrypts, passkey and favorite kept" \
    '{"keyed":true,"favorite":true,"password":"pw-k","passkeys":1,"history":["kp"],"notes":"changed"}' \
    "$(item keyed '{keyed, favorite, password: .login.password, passkeys: .login.passkeys, history, notes}')"

echo "== attachments"
head -c 300000 /dev/urandom >"$WORK/bin.dat"
echo hello >"$WORK/text.txt"
rbw attachment add flags --file "$WORK/bin.dat" --file "$WORK/text.txt"
rbw attachment add keyed --file "$WORK/text.txt"
check "attachments readable by other clients" \
    "$(sha256sum <"$WORK/bin.dat" | cut -d' ' -f1)" \
    "$(item flags '.attachments[] | select(.[0] == "bin.dat") | .[1]' | tr -d '"')"
check "attachment on keyed entry" "$(sha256sum <"$WORK/text.txt" | cut -d' ' -f1)" "$(item keyed '.attachments[0][1]' | tr -d '"')"
(cd "$WORK" && rbw attachment get flags --name bin.dat -o out.dat)
check "attachment get roundtrip" "$(sha256sum <"$WORK/bin.dat")" "$(sha256sum <"$WORK/out.dat")"
check "attachment get refuses to overwrite" 1 "$(cd "$WORK" && rbw attachment get flags --name bin.dat -o out.dat >/dev/null 2>&1; echo $?)"
check "attachment to stdout" hello "$(rbw attachment get keyed -o -)"
check "get --raw lists attachments" '["bin.dat","text.txt"]' "$(rbw get --raw flags | jq -c '[.attachments[].file_name]')"
rbw attachment rm flags --name text.txt
check "attachment rm" '["bin.dat"]' "$(rbw get --raw flags | jq -c '[.attachments[].file_name]')"

echo "== folders, trash"
rbw folder add Empty
rbw folder rename Empty Renamed
check "folder add/rename" '["Altro","Prove","Renamed"]' "$(rbw folder list --raw | jq -c '[.[].name] | sort')"
rbw folder rm Altro
check "folder rm keeps entries" null "$(rbw get --raw legacy2 | jq .folder)"
rbw rm nota
check "rm moves to trash" nota "$(rbw trash)"
check "trashed entry hidden" 1 "$(rbw get nota >/dev/null 2>&1; echo $?)"
rbw restore nota
check "restore" "testo nota" "$(rbw get --raw nota | jq -r .notes)"
rbw rm generated --permanent
check "rm --permanent" "" "$(rbw trash)"

echo "== rofi-rbw"
if python3 -c 'import rofi_rbw' 2>/dev/null; then
    check "rofi-rbw reads every entry" 4 "$(python3 -c '
from rofi_rbw.rbw import Rbw
r = Rbw()
print(sum(1 for e in r.list_entries() if r.fetch_credentials(e)))')"
fi

echo "== concurrent writes and reads"
# every save of the agent used to truncate the cache before writing it: a
# command reading it in that moment failed with "EOF while parsing", and the
# agent took the unreadable file for "not logged in" and started a new
# interactive login (master password and 2fa) while the vault was in use
printf '#!/bin/sh\necho call >> %s/pinentry.log\nexec %s "$@"\n' "$WORK" "$ROOT/tests/vw/pinentry-test" >"$WORK/bin/pinentry-log"
chmod +x "$WORK/bin/pinentry-log"
rbw config set pinentry "$WORK/bin/pinentry-log"
rbw unlock    # config set stops the agent: start it before counting prompts
: >"$WORK/pinentry.log"
(while [ ! -e "$WORK/stop" ]; do
    rbw list >/dev/null 2>>"$WORK/readers.err" || echo list >>"$WORK/readers.fail"
    rbw get flags >/dev/null 2>>"$WORK/readers.err" || echo get >>"$WORK/readers.fail"
done) &
(while [ ! -e "$WORK/stop" ]; do
    rbw sync 2>>"$WORK/readers.err" || echo sync >>"$WORK/readers.fail"
done) &
for i in $(seq 1 40); do
    rbw edit flags --add-uri "https://s$i.example" 2>>"$WORK/writers.err" || echo "edit $i" >>"$WORK/writers.fail"
done
touch "$WORK/stop"
wait
check "no command failed while the cache was rewritten" 0 "$(cat "$WORK/readers.fail" "$WORK/writers.fail" 2>/dev/null | wc -l)"
check "no login prompt while the vault was in use" 0 "$(wc -l <"$WORK/pinentry.log")"
check "every concurrent edit landed" 40 "$(item flags '.login.uris | length')"
check "no temporary files left next to the cache" 1 "$(find "$HOME/.cache/rbw-rbwtest" -maxdepth 1 -type f | wc -l)"
cat "$WORK/readers.err" "$WORK/writers.err" 2>/dev/null | sort | uniq -c | head -5

echo "== parallel commands on a stopped agent"
# each command used to find the agent locked and open its own pinentry, and a
# command that couldn't reach the agent yet stopped the one another command
# had just started
for round in 1 2 3; do
    rbw stop-agent
    : >"$WORK/pinentry.log"
    rm -f "$WORK/parallel.fail"
    for i in $(seq 1 8); do
        (rbw get flags >/dev/null 2>>"$WORK/parallel.err" || echo "get $i" >>"$WORK/parallel.fail") &
    done
    wait
    check "round $round: no command failed" 0 "$(cat "$WORK/parallel.fail" 2>/dev/null | wc -l)"
    check "round $round: one master password prompt" 1 "$(wc -l <"$WORK/pinentry.log")"
done
rbw lock
: >"$WORK/pinentry.log"
rm -f "$WORK/parallel.fail"
for i in $(seq 1 8); do
    (rbw get flags >/dev/null 2>>"$WORK/parallel.err" || echo "get $i" >>"$WORK/parallel.fail") &
done
wait
check "locked agent: no command failed" 0 "$(cat "$WORK/parallel.fail" 2>/dev/null | wc -l)"
check "locked agent: one master password prompt" 1 "$(wc -l <"$WORK/pinentry.log")"
sort "$WORK/parallel.err" 2>/dev/null | uniq -c | head -5
rbw config set pinentry "$ROOT/tests/vw/pinentry-test"

echo "== expired login"
rbw config set persistent_login false
setdb '.access_token="x.eyJzdWIiOiJ4In0.x" | .refresh_token="garbage"'
check "rejected refresh token fails the sync" 1 "$(rbw sync >/dev/null 2>&1; echo $?)"
check "and drops the tokens" '[null,null]' "$(jq -c '[.access_token, .refresh_token]' "$(db)")"
check "and notifies once" 1 "$(wc -l <"$WORK/notify.log")"

read -r ID SECRET <<<"$(bw apikey)"
rbw config set persistent_login true
setdb 'del(.access_token, .refresh_token) | .api_key_login=false'
RBW_TEST_APIKEY_ID=$ID RBW_TEST_APIKEY_SECRET=$SECRET rbw login
check "login with the api key (no 2fa)" true "$(jq .api_key_login "$(db)")"
setdb '.access_token="x.eyJzdWIiOiJ4In0.x"'
echo pw-api | RBW_TEST_APIKEY_ID=user.wrong rbw edit flags --password-stdin
check "expired access token: silent api key login from memory" pw-api "$(rbw get flags)"
rbw stop-agent
setdb '.access_token="x.eyJzdWIiOiJ4In0.x"'
RBW_TEST_APIKEY_ID=$ID RBW_TEST_APIKEY_SECRET=$SECRET rbw sync
check "background sync logs in again after agent restart" pw-api "$(rbw get flags)"

echo "== biometric unlock"
# polkit is faked (the real one needs someone at the keyboard): pkcheck logs
# each call and answers with the exit code in pk.answer. systemd-creds is the
# real one when it supports user credentials.
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/pkaction"
printf '#!/bin/sh\necho "$*" >> %s/pkcheck.log\nexit "$(cat %s/pk.answer)"\n' "$WORK" "$WORK" >"$WORK/bin/pkcheck"
chmod +x "$WORK/bin/pkaction" "$WORK/bin/pkcheck"
echo 0 >"$WORK/pk.answer"
rbw config set pinentry "$WORK/bin/pinentry-log"
rbw unlock
: >"$WORK/pinentry.log"
rbw biometric enroll
STORE=$(jq -r .biometric_store "$HOME/.config/rbw-rbwtest/config.json")
check "enroll asks for the master password once" 1 "$(wc -l <"$WORK/pinentry.log")"
check "enroll enables biometric unlock" true "$(jq .biometric "$HOME/.config/rbw-rbwtest/config.json")"
rbw lock
check "lock keeps the keys" '[true,true]' "$(rbw status --json | jq -c '[.locked, .keys_in_memory]')"
check "a locked agent refuses to decrypt" 1 "$(echo '{"environment":null,"action":{"type":"Decrypt","cipherstring":"'"$(jq -r '.entries[0].name' "$(db)")"'","entry_key":null,"org_id":null}}' | SOCK="${XDG_RUNTIME_DIR:-/tmp}/rbw-rbwtest/socket" python3 -I -c '
import socket,sys,os
s=socket.socket(socket.AF_UNIX); s.connect(os.environ["SOCK"]); s.sendall(sys.stdin.buffer.read()+b"\n")
print(1 if b"Error" in s.makefile("rb").readline() else 0)')"
: >"$WORK/pinentry.log"; : >"$WORK/pkcheck.log"
check "unlock with the kept keys" pw-api "$(rbw get flags)"
check "  asked polkit once" 1 "$(wc -l <"$WORK/pkcheck.log")"
check "  and no pinentry" 0 "$(wc -l <"$WORK/pinentry.log")"
rbw lock --hard
check "lock --hard drops the keys" false "$(rbw status --json | jq .keys_in_memory)"
check "unlock with the saved password ($STORE)" pw-api "$(rbw get flags)"
check "  still no pinentry" 0 "$(wc -l <"$WORK/pinentry.log")"
rbw stop-agent
check "first unlock after the agent starts is biometric" pw-api "$(rbw get flags)"
check "  still no pinentry" 0 "$(wc -l <"$WORK/pinentry.log")"
echo 1 >"$WORK/pk.answer"
rbw lock
check "polkit refused: falls back to the master password" pw-api "$(rbw get flags)"
check "  with one pinentry" 1 "$(wc -l <"$WORK/pinentry.log")"
echo 0 >"$WORK/pk.answer"
rbw biometric disable
check "disable forgets the password" '[false,null]' "$(jq -c '[.biometric, .biometric_store]' "$HOME/.config/rbw-rbwtest/config.json")"
check "  and removes the credential" no "$([ -e "$HOME/.local/share/rbw-rbwtest/biometric.cred" ] && echo yes || echo no)"
rbw lock
check "without biometric, lock drops the keys" false "$(rbw status --json | jq .keys_in_memory)"
rbw config set pinentry "$ROOT/tests/vw/pinentry-test"

echo "== status and usage"
rbw stop-agent
check "status doesn't start the agent" '[false,true,true]' "$(rbw status --json | jq -c '[.agent, .logged_in, .locked]')"
check "  really" 1 "$(rbw unlocked >/dev/null 2>&1; echo $?)"
rm -f "$HOME/.local/share/rbw-rbwtest/usage.json"
rbw config set sort_by_usage true
rbw get nota >/dev/null; rbw get nota >/dev/null; rbw get flags >/dev/null
check "list puts the most used first" "nota flags" "$(rbw list | head -2 | tr '\n' ' ' | sed 's/ $//')"
check "usage keeps only ids" 0 "$(grep -c -E 'nota|flags' "$HOME/.local/share/rbw-rbwtest/usage.json")"
rbw config set sort_by_usage false
check "and alphabetical without it" "$(rbw list | sort | head -1)" "$(rbw list | head -1)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
