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

echo "== types, organizations, archive"
cat >"$WORK/editor-card" <<'EOF'
#!/bin/sh
sed -i 's/^cardholder: .*/cardholder: Mario Rossi/; s/^number: .*/number: 4111111111111111/; s/^exp month: .*/exp month: 12/; s/^code: .*/code: 123/' "$1"
EOF
chmod +x "$WORK/editor-card"
VISUAL=$WORK/editor-card script -qec "rbw add visa --type card" /dev/null >/dev/null
check "add a card in the editor" '{"cardholderName":"Mario Rossi","number":"4111111111111111","expMonth":"12","code":"123"}' \
    "$(item visa '.card | {cardholderName, number, expMonth, code}')"
cat >"$WORK/editor-code" <<'EOF'
#!/bin/sh
sed -i 's/^code: .*/code: 999/' "$1"
EOF
chmod +x "$WORK/editor-code"
VISUAL=$WORK/editor-code script -qec "rbw edit visa" /dev/null >/dev/null
check "edit a card changes only its code" '{"number":"4111111111111111","code":"999"}' "$(item visa '.card | {number, code}')"
cat >"$WORK/editor-identity" <<'EOF'
#!/bin/sh
sed -i 's/^first name: .*/first name: Mario/; s/^email: .*/email: mario@example.com/' "$1"
EOF
chmod +x "$WORK/editor-identity"
VISUAL=$WORK/editor-identity script -qec "rbw add io --type identity" /dev/null >/dev/null
check "add an identity" '{"firstName":"Mario","email":"mario@example.com"}' "$(item io '.identity | {firstName, email}')"
rbw add chiave --type ssh-key --no-edit
item chiave '.sshKey.privateKey' | jq -r . >"$WORK/id_test"
chmod 600 "$WORK/id_test"
check "add an ssh key generates an ed25519 key" "$(ssh-keygen -y -f "$WORK/id_test")" "$(item chiave '.sshKey.publicKey' | jq -r .)"
check "  with its fingerprint" "$(ssh-keygen -lf "$WORK/id_test" | cut -d' ' -f2)" "$(item chiave '.sshKey.keyFingerprint' | jq -r .)"
check "unknown type refused" 1 "$(rbw add x --type bogus --no-edit >/dev/null 2>&1; echo $?)"

bw mkorg Azienda Generale Progetti >/dev/null
rbw sync
check "sync keeps organizations and collections" '{"orgs":["Azienda"],"collections":2}' \
    "$(jq -c '{orgs: [.organizations[].name], collections: (.collections | length)}' "$(db)")"
rbw add interno utente --org Azienda --collection Progetti --no-edit
check "add in an organization collection" '{"org":"Azienda","collections":["Progetti"],"username":"utente"}' \
    "$(item interno '{org, collections, username: .login.username}')"
check "  and rbw reads it back" utente "$(rbw get interno --field username)"
check "an organization item needs a collection" 1 "$(rbw add y --org Azienda --no-edit >/dev/null 2>&1; echo $?)"
check "unknown collection refused" 1 "$(rbw add y --org Azienda --collection Nope --no-edit >/dev/null 2>&1; echo $?)"

rbw archive io
check "archive" true "$(item io .archived)"
check "  synced into the db" true "$(jq -r '.entries[] | select(.id == "'"$(rbw get --raw io | jq -r .id)"'") | .archived' "$(db)")"
check "  still listed for rofi-rbw" 1 "$(rbw list | grep -cx io)"
rbw unarchive io
check "unarchive" false "$(item io .archived)"

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

echo "== unlock options"
# polkit is faked (the real one needs someone at the keyboard): pkcheck logs
# each call and answers with the exit code in pk.answer. The pinentry
# answers PIN prompts from pin.answer, and logs every call. systemd-creds is
# the real one.
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/pkaction"
printf '#!/bin/sh\necho "$*" >> %s/pkcheck.log\nexit "$(cat %s/pk.answer)"\n' "$WORK" "$WORK" >"$WORK/bin/pkcheck"
cat >"$WORK/bin/pinentry-pin" <<PINENTRY
#!/bin/sh
echo call >> $WORK/pinentry.log
echo "OK Pleased to meet you"
pin=""
while IFS= read -r line; do
  case "\$line" in
    SETPROMPT\ PIN*) pin=1; echo OK ;;
    GETPIN*) if [ -n "\$pin" ]; then echo "D \$(cat $WORK/pin.answer)"; else echo "D $PW"; fi; pin=""; echo OK ;;
    BYE*) echo "OK closing connection"; exit 0 ;;
    *) echo OK ;;
  esac
done
PINENTRY
chmod +x "$WORK/bin/pkaction" "$WORK/bin/pkcheck" "$WORK/bin/pinentry-pin"
echo 0 >"$WORK/pk.answer"
echo 2468 >"$WORK/pin.answer"
CONF="$HOME/.config/rbw-rbwtest/config.json"
agent_pid() { cat "${XDG_RUNTIME_DIR:-/tmp}/rbw-rbwtest/pidfile" 2>/dev/null; }
reset_logs() { : >"$WORK/pinentry.log"; : >"$WORK/pkcheck.log"; }
prompts() { wc -l <"$WORK/pinentry.log"; }
pkchecks() { wc -l <"$WORK/pkcheck.log"; }
rbw config set pinentry "$WORK/bin/pinentry-pin"
rbw unlock
reset_logs

rbw remember-password
check "remember-password asks for the master password once" 1 "$(prompts)"
STORE=$(jq -r .saved_password "$CONF")
PID=$(agent_pid)
rbw config set system_auth true
check "changing a lock setting keeps the agent running" "$PID" "$(agent_pid)"
check "  and unlocked" false "$(rbw status --json | jq .locked)"

rbw lock
check "lock keeps the keys" '[true,true]' "$(rbw status --json | jq -c '[.locked, .keys_in_memory]')"
check "a locked agent refuses to decrypt" 1 "$(echo '{"environment":null,"action":{"type":"Decrypt","cipherstring":"'"$(jq -r '.entries[0].name' "$(db)")"'","entry_key":null,"org_id":null}}' | SOCK="${XDG_RUNTIME_DIR:-/tmp}/rbw-rbwtest/socket" python3 -I -c '
import socket,sys,os
s=socket.socket(socket.AF_UNIX); s.connect(os.environ["SOCK"]); s.sendall(sys.stdin.buffer.read()+b"\n")
print(1 if b"Error" in s.makefile("rb").readline() else 0)')"
reset_logs
check "system unlock with the kept keys" pw-api "$(rbw get flags)"
check "  one polkit check, no pinentry" "1 0" "$(pkchecks) $(prompts)"
check "  and no more checks while unlocked" pw-api "$(rbw get flags)"
check "  (still one)" 1 "$(pkchecks)"
rbw lock --hard
check "lock --hard drops the keys" false "$(rbw status --json | jq .keys_in_memory)"
reset_logs
check "system unlock with the saved password ($STORE)" pw-api "$(rbw get flags)"
check "  no pinentry" 0 "$(prompts)"
rbw stop-agent
check "system unlock right after the agent starts" pw-api "$(rbw get flags)"
check "  no pinentry" 0 "$(prompts)"
echo 1 >"$WORK/pk.answer"
rbw lock
reset_logs
check "polkit refused: the master password" pw-api "$(rbw get flags)"
check "  one pinentry" 1 "$(prompts)"
echo 0 >"$WORK/pk.answer"

rbw config set system_auth false
rbw config set auto_unlock true
rbw lock --hard
reset_logs
check "auto_unlock: unlocks with the saved password" pw-api "$(rbw get flags)"
check "  no pinentry, no polkit" "0 0" "$(prompts) $(pkchecks)"
rbw stop-agent
check "auto_unlock right after the agent starts" pw-api "$(rbw get flags)"
check "  no pinentry, no polkit" "0 0" "$(prompts) $(pkchecks)"
if command -v tmux >/dev/null; then
    rbw config set tui_auth true
    tui_once() {
        tmux kill-session -t rbw-auth 2>/dev/null || true
        tmux new-session -d -s rbw-auth -x 100 -y 20 "env PATH='$PATH' RBW_PROFILE=rbwtest rbw tui; sleep 5"
        for _ in $(seq 1 50); do tmux capture-pane -p -t rbw-auth | grep -q -E '❯|not authorized' && break; sleep 0.1; done
        tmux capture-pane -p -t rbw-auth | grep -c '❯'
        tmux kill-session -t rbw-auth 2>/dev/null || true
    }
    reset_logs
    check "tui_auth: the tui asks polkit" "1 1" "$(tui_once) $(pkchecks)"
    check "  once per login session" "1 1" "$(tui_once) $(pkchecks)"
    rbw stop-agent
    echo 1 >"$WORK/pk.answer"
    reset_logs
    check "  refused: the tui doesn't open" 0 "$(tui_once)"
    check "  but rbw get still works" pw-api "$(rbw get flags)"
    echo 0 >"$WORK/pk.answer"
    rbw config set tui_auth false
fi
rbw config set auto_unlock false
reset_logs
rbw pin set
check "pin set asks twice" 2 "$(prompts)"
rbw lock
check "with a pin, lock keeps the keys" true "$(rbw status --json | jq .keys_in_memory)"
reset_logs
check "pin unlock" pw-api "$(rbw get flags)"
check "  one pinentry, no polkit" "1 0" "$(prompts) $(pkchecks)"
rbw stop-agent
reset_logs
check "pin unlock after a restart (saved password)" pw-api "$(rbw get flags)"
check "  one pinentry" 1 "$(prompts)"
echo 0000 >"$WORK/pin.answer"
rbw lock
reset_logs
check "five wrong pins: the master password" pw-api "$(rbw get flags)"
check "  five pin prompts and one for the password" 6 "$(prompts)"
echo 2468 >"$WORK/pin.answer"
rbw lock
reset_logs
check "the right pin works again after the master password" pw-api "$(rbw get flags)"
check "  one pinentry" 1 "$(prompts)"

rbw config set timeout_action forget
rbw lock
check "timeout_action forget drops the keys" false "$(rbw status --json | jq .keys_in_memory)"
rbw config set timeout_action lock
rbw get flags >/dev/null
rbw config set lock_timeout 2
rbw get flags >/dev/null
for _ in $(seq 1 40); do [ "$(rbw status --json | jq .locked)" = true ] && break; sleep 0.1; done
check "lock_timeout 2 locks after two seconds" '[true,true]' "$(rbw status --json | jq -c '[.locked, .keys_in_memory]')"
rbw config set lock_timeout never
check "lock_timeout never is stored as 0" 0 "$(jq .lock_timeout "$CONF")"
rbw config set lock_timeout 4h
check "lock_timeout 4h" 14400 "$(jq .lock_timeout "$CONF")"

rbw pin clear
rbw lock
check "without pin or system unlock, lock drops the keys" false "$(rbw status --json | jq .keys_in_memory)"
rbw forget-password
check "forget-password removes the credential" '[null,"no"]' "$(jq -c '[.saved_password]' "$CONF" | jq -c '. + ["'"$([ -e "$HOME/.local/share/rbw-rbwtest/biometric.cred" ] && echo yes || echo no)"'"]')"
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

echo "== tui"
if command -v tmux >/dev/null; then
    screen() { tmux capture-pane -p -t rbw-e2e 2>/dev/null; }
    wait_screen() {
        for _ in $(seq 1 50); do screen | grep -q -- "$1" && return 0; sleep 0.1; done
        return 1
    }
    tmux kill-session -t rbw-e2e 2>/dev/null || true
    tmux new-session -d -s rbw-e2e -x 140 -y 40 "env PATH='$PATH' RBW_PROFILE=rbwtest RBW_TEST_PIN='$PW' VISUAL='$WORK/editor-card' rbw tui"
    check "tui starts with every entry listed" 0 "$(wait_screen "/$(rbw list | wc -l)\$" ; echo $?)"
    tmux send-keys -t rbw-e2e 'flags'
    check "typing filters" 0 "$(wait_screen ' 1/' ; echo $?)"
    check "secrets are masked" 0 "$(wait_screen '••••' ; echo $?)"
    tmux send-keys -t rbw-e2e C-r
    check "^R reveals them" 0 "$(wait_screen 'pw-api' ; echo $?)"
    rbw lock
    check "a lock elsewhere hides the details" 0 "$(wait_screen 'locked: Enter' ; echo $?)"
    check "  and the secrets are gone from the screen" 0 "$(screen | grep -c 'pw-api')"
    tmux send-keys -t rbw-e2e Tab
    check "Tab unlocks again" 0 "$(wait_screen 'password' ; echo $?)"
    # back from the fields, clear the filter
    # one at a time: escapes sent together read as alt sequences
    for _ in 1 2; do tmux send-keys -t rbw-e2e Escape; sleep 0.2; done
    check "the sidebar lists the organization" 0 "$(wait_screen 'Azienda' ; echo $?)"
    tmux send-keys -t rbw-e2e Left Down
    check "favorites view" 0 "$(wait_screen '╭ Favorites ─' ; echo $?)"
    check "  lists the favorites" 0 "$(wait_screen ' 2/' ; echo $?)"
    tmux send-keys -t rbw-e2e Enter C-f
    check "^F removes a favorite" 0 "$(wait_screen 'removed from the favorites' ; echo $?)"
    check "  and the view follows" 0 "$(wait_screen ' 1/' ; echo $?)"
    tmux send-keys -t rbw-e2e Left Up Enter
    tmux send-keys -t rbw-e2e 'visa'
    check "back to all items" 0 "$(wait_screen '╭ All items ─' ; echo $?)"
    tmux send-keys -t rbw-e2e C-a
    check "^A archives" 0 "$(wait_screen 'archived' ; echo $?)"
    check "  and hides it from all items" 0 "$(wait_screen ' 0/' ; echo $?)"
    check "  on the server" true "$(item visa .archived)"
    tmux send-keys -t rbw-e2e C-w
    rbw rm interno
    tmux send-keys -t rbw-e2e Left End
    check "trash view lists the trash" 0 "$(wait_screen 'interno  deleted' ; echo $?)"
    tmux send-keys -t rbw-e2e Enter Enter
    check "Enter restores from the trash" 0 "$(wait_screen 'restored' ; echo $?)"
    check "  on the server" false "$(item interno .deleted)"
    tmux send-keys -t rbw-e2e Left Up
    check "archive view" 0 "$(wait_screen '╭ Archive ─' ; echo $?)"
    tmux send-keys -t rbw-e2e Enter C-a
    check "^A unarchives there" 0 "$(wait_screen 'unarchived' ; echo $?)"
    tmux send-keys -t rbw-e2e Left Home Enter
    tmux send-keys -t rbw-e2e C-g
    check "^G opens the generator" 0 "$(wait_screen '‹ 20 characters ›' ; echo $?)"
    tmux send-keys -t rbw-e2e Down Left
    check "  ↓ ← shortens it" 0 "$(wait_screen '‹ 19 characters ›' ; echo $?)"
    tmux send-keys -t rbw-e2e Escape
    sleep 0.2
    tmux send-keys -t rbw-e2e 'tessera'
    tmux send-keys -t rbw-e2e C-n
    check "^N asks type and vault" 0 "$(wait_screen 'Vault       ‹ My vault ›' ; echo $?)"
    tmux send-keys -t rbw-e2e Right Down Right Down Down Space
    check "  Space lists the folders" 0 "$(wait_screen '╭ Folder ─' ; echo $?)"
    tmux send-keys -t rbw-e2e 'prov'
    check "  typing filters them" 0 "$(wait_screen '1/' ; echo $?)"
    tmux send-keys -t rbw-e2e Enter
    check "  Enter picks one" 0 "$(wait_screen 'Folder      ‹ Prove ›' ; echo $?)"
    tmux send-keys -t rbw-e2e Enter
    check "  and creates it" 0 "$(wait_screen 'added' ; echo $?)"
    check "  in the picked folder" Prove "$(rbw get --raw tessera | jq -r .folder)"
    check "  a card in the organization, named after the filter" \
        '{"type":3,"org":"Azienda","number":"4111111111111111"}' "$(item tessera '{type, org, number: .card.number}')"
    for _ in 1 2; do tmux send-keys -t rbw-e2e Escape; sleep 0.2; done
    for _ in $(seq 1 30); do tmux has-session -t rbw-e2e 2>/dev/null || break; sleep 0.1; done
    check "Esc quits" 1 "$(tmux has-session -t rbw-e2e 2>/dev/null; echo $?)"
else
    echo "skipped (no tmux)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
