#!/usr/bin/env bash
# End-to-end tests: throwaway GnuPG home + fixture store -> export -> golden compare.
# Usage: tests/run.sh [--update]   (--update rewrites tests/expected.json)

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname -- "$TESTS_DIR")"
EXPORTER="$ROOT/pass-exporter"
FIXTURES="$TESTS_DIR/fixtures/store"
EXPECTED="$TESTS_DIR/expected.json"
UPDATE=false
[[ "${1:-}" == --update ]] && UPDATE=true

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pass-exporter-test.XXXXXX")"
export GNUPGHOME="$WORK/gnupg"
export NO_COLOR=1
STORE="$WORK/store"
OUT="$WORK/out/export.json"

cleanup() {
    gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    rm -rf -- "$WORK"
}
trap cleanup EXIT

PASS=0 FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'ok   - %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL - %s\n' "$1"; }
check() { local name="$1"; shift; if "$@"; then ok "$name"; else fail "$name"; fi; }

# --- setup: key + encrypted fixture store --------------------------------
mkdir -p "$GNUPGHOME" "$STORE"
chmod 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-gen-key 'pass-exporter test <test@example.invalid>' future-default default never 2>/dev/null
KEYID="$(gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1=="sec"{print $5; exit}')"
printf '%s\n' "$KEYID" >"$STORE/.gpg-id"
mkdir -p "$STORE/.public-keys"
gpg --batch --armor --export "$KEYID" >"$STORE/.public-keys/$KEYID"

while IFS= read -r -d '' f; do
    rel="${f#"$FIXTURES"/}"
    mkdir -p "$STORE/$(dirname -- "$rel")"
    gpg --batch --quiet --yes --trust-model always -r "$KEYID" \
        -o "$STORE/${rel%.txt}.gpg" --encrypt -- "$f" 2>/dev/null
done < <(find "$FIXTURES" -type f -name '*.txt' -print0)

# Binary entry (not valid UTF-8, contains NUL).
mkdir -p "$STORE/Blobs"
printf 'bin\x00\xff\xfe' | gpg --batch --quiet --trust-model always -r "$KEYID" -o "$STORE/Blobs/binary.gpg" --encrypt 2>/dev/null
mkdir -p "$STORE/empty-dir"

SECRETS=(gh-fake-Pa55 fake-hunter2 fake-proton-pw fake-pw123 FAKEFAKEFAKEFAKE FAKEOPENSSHKEY
         fake-wifi-pw abandon fake-monero-pw 1111-2222 ghp_FAKETOKEN AKIAABCDEFGHIJKLMNOP
         fake-aws-secret fake-restic-pw fake-admin-pw fake-pin JBSWY3DPEHPK3PXP
         FAKE-SECRET-KEY-A3 fake-restic-user-pw fake-gamer-pw "alpha beta" "gamma delta" epsilon)

no_secrets_in() {
    local s
    for s in "${SECRETS[@]}"; do
        if grep -qF -- "$s" "$1"; then
            printf '     leaked: %s\n' "$s" >&2
            return 1
        fi
    done
}

shm_count() { find /dev/shm -maxdepth 1 -name 'pass-exporter.*' 2>/dev/null | wc -l; }
SHM_BEFORE="$(shm_count)"

# --- dry run ---------------------------------------------------------------
"$EXPORTER" export -s "$STORE" -o "$OUT" --dry-run -v >"$WORK/dry.out" 2>"$WORK/dry.err"
check "dry run writes nothing" test ! -e "$OUT"
check "dry run lists every entry" test "$(grep -c -e '^Blobs' -e '^Github' "$WORK/dry.out")" -eq 2
check "dry run (-v) never logs secrets on stderr" no_secrets_in "$WORK/dry.err"
check "dry run never prints secrets on stdout" no_secrets_in "$WORK/dry.out"

# --- export ------------------------------------------------------------------
"$EXPORTER" export -s "$STORE" -o "$OUT" -v 2>"$WORK/export.err"
check "export file created" test -f "$OUT"
check "export file mode is 600" test "$(stat -c %a "$OUT")" = 600
check "output dir mode is 700" test "$(stat -c %a "$(dirname "$OUT")")" = 700
check "export (-v) never logs secrets" no_secrets_in "$WORK/export.err"
check "no leftover temp files in output dir" test "$(find "$(dirname "$OUT")" -name '.pass-export.*' | wc -l)" -eq 0
check "tmpfs work dir removed" test "$(shm_count)" -eq "$SHM_BEFORE"
check "entry count is 21" test "$(jq '.entries | length' "$OUT")" -eq 21
check "validate passes" "$EXPORTER" validate -o "$OUT" -q
check "summary never prints secrets" bash -c "'$EXPORTER' summary -o '$OUT' >'$WORK/sum.out' 2>&1"
check "summary output is secret free" no_secrets_in "$WORK/sum.out"

# --- golden compare (volatile metadata removed) ------------------------------
normalize() { jq -S 'del(.exported_at, .source.store, .source.gpg_id)' "$1"; }
if [[ "$UPDATE" == true ]]; then
    normalize "$OUT" >"$EXPECTED"
    ok "expected.json updated"
else
    if diff -u "$EXPECTED" <(normalize "$OUT") >"$WORK/diff.txt"; then
        ok "export matches expected.json"
    else
        fail "export differs from expected.json"
        cat "$WORK/diff.txt"
    fi
fi

# --- overwrite protection, filter, validation errors -------------------------
check "refuses to overwrite without --force" bash -c "! '$EXPORTER' export -s '$STORE' -o '$OUT' -q 2>/dev/null"
"$EXPORTER" export -s "$STORE" -o "$OUT" --force --filter 'Misc/*' -q 2>/dev/null
check "--filter limits entries" test "$(jq '.entries | length' "$OUT")" -eq 2
jq '.entries[0].type = "bogus" | .entries[1].title = ""' "$OUT" >"$WORK/bad.json"
check "validate rejects bad edits" bash -c "! '$EXPORTER' validate -o '$WORK/bad.json' -q 2>/dev/null"

# --- import: proton backend against a mock pass-cli ---------------------------
export PROTON_CLI="$TESTS_DIR/mock-pass-cli" MOCK_PASS_DIR="$WORK/mock"
"$EXPORTER" export -s "$STORE" -o "$OUT" --force -q 2>/dev/null
mock_items() { cat "$MOCK_PASS_DIR"/items/*/*.json 2>/dev/null | jq -s "."; }

for v in Personal personal ' PERSONAL ' ''; do
    check "import refuses vault '$v'" bash -c "! '$EXPORTER' import -b proton -o '$OUT' --vault '$v' --apply --yes >/dev/null 2>&1"
done
check "refused vaults never reach pass-cli" test ! -e "$MOCK_PASS_DIR/argv.log"

"$EXPORTER" import -b proton -o "$OUT" >"$WORK/imp-dry.out" 2>"$WORK/imp-dry.err" || true
check "import dry run creates nothing" test ! -d "$MOCK_PASS_DIR/items/-sid-pass-exporter"
check "import dry run plans 21 creates" grep -q "plan for vault 'pass-exporter': create=21 exists=0" "$WORK/imp-dry.err"
check "import dry run output is secret free" no_secrets_in "$WORK/imp-dry.out"

check "import --apply without --yes refuses when not interactive" \
    bash -c "! '$EXPORTER' import -b proton -o '$OUT' --apply </dev/null >/dev/null 2>&1"

"$EXPORTER" import -b proton -o "$OUT" --apply --yes -v >"$WORK/imp.out" 2>"$WORK/imp.err" || true
check "import creates the default vault 'pass-exporter'" \
    test "$(jq -r '[.vaults[].name] | join(",")' "$MOCK_PASS_DIR/vaults.json")" = pass-exporter
check "import creates 21 items + 2 companions" test "$(mock_items | jq length)" -eq 23
check "import never puts secrets on argv" no_secrets_in "$MOCK_PASS_DIR/argv.log"
check "import (-v) never logs secrets" no_secrets_in "$WORK/imp.err"
check "login keeps username, url and totp" test "$(mock_items | jq -r '.[] | select(.template.title == "github_user_octocat")
    | .template | "\(.username) \(.urls[0]) \(.totp_uri | startswith("otpauth://"))"')" = "octocat https://github.com true"
check "login extras go to a companion custom item" test "$(mock_items | jq -r '.[] | select(.template.title == "github_user_octocat_extras")
    | .kind + " " + (.template.sections[0].fields[0] | .field_name + ":" + .field_type)')" = "custom recovery:hidden"
check "password type becomes custom with hidden field" test "$(mock_items | jq -r '.[] | select(.template.title == "misc_my_pin")
    | .kind + " " + (.template.sections[0].fields[0] | .field_name + ":" + .field_type)')" = "custom password:hidden"
check "wifi gets ssid from path" test "$(mock_items | jq -r '.[] | select(.kind == "wifi") | .template.ssid')" = mynet
check "ssh key imported from private key file" test "$(mock_items | jq -r '.[] | select(.kind == "ssh-key") | .private_key | startswith("-----BEGIN OPENSSH")')" = true
check "import leaves no temp files" test "$(shm_count)" -eq "$SHM_BEFORE"

"$EXPORTER" import -b proton -o "$OUT" --apply --yes 2>"$WORK/imp2.err" >/dev/null || true
check "re-import skips existing titles" grep -q "plan for vault 'pass-exporter': create=0 exists=21" "$WORK/imp2.err"
check "re-import creates nothing new" test "$(mock_items | jq length)" -eq 23
# Defence in depth: the name resolves to a share id that belongs to "Personal".
export MOCK_PASS_DIR="$WORK/mock-personal"
mkdir -p "$MOCK_PASS_DIR"
echo '{"vaults":[{"name":"Personal","share_id":"sid-X"},{"name":"pass-exporter","share_id":"sid-X"}]}' \
    >"$MOCK_PASS_DIR/vaults.json"
check "backend refuses a share id owned by Personal" \
    bash -c "! '$EXPORTER' import -b proton -o '$OUT' --apply --yes >/dev/null 2>&1"
check "nothing created in Personal" test ! -d "$MOCK_PASS_DIR/items/sid-X" -o -z "$(ls -A "$MOCK_PASS_DIR/items/sid-X" 2>/dev/null)"
unset PROTON_CLI MOCK_PASS_DIR

# --- interrupted run leaves nothing behind -----------------------------------
mkdir -p "$WORK/slowbin"
cat >"$WORK/slowbin/gpg" <<EOF
#!/usr/bin/env bash
case " \$* " in *" --decrypt "*) sleep 1 ;; esac
exec $(command -v gpg) "\$@"
EOF
chmod 755 "$WORK/slowbin/gpg"
rm -f -- "$OUT"
PATH="$WORK/slowbin:$PATH" "$EXPORTER" export -s "$STORE" -o "$OUT" -q 2>/dev/null &
pid=$!
sleep 2.5
kill -TERM "$pid"
wait "$pid" 2>/dev/null || true
check "interrupted: no export file" test ! -e "$OUT"
check "interrupted: no temp files in output dir" test "$(find "$(dirname "$OUT")" -name '.pass-export.*' | wc -l)" -eq 0
check "interrupted: tmpfs work dir removed" test "$(shm_count)" -eq "$SHM_BEFORE"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
