# shellcheck shell=bash
# Proton Pass backend, using Proton's official CLI (pass-cli).
# Implements the contract in backends/README.md. Payloads come from
# backends/proton.jq (backend_payload). Secrets are only ever passed to
# pass-cli on stdin or as a 0600 file on tmpfs, never on argv.

PROTON_CLI="${PROTON_CLI:-pass-cli}"

# Always pass option values as --option=VALUE: Proton share ids can start
# with "-" (e.g. "-Yab…"), which pass-cli would otherwise parse as a flag.

backend_check_deps() {
    require_cmds "$PROTON_CLI" jq
}

backend_check_auth() {
    local info user
    if ! info="$("$PROTON_CLI" info 2>&1)"; then
        log_error "$info"
        die "pass-cli is not usable; log in first with: pass-cli login"
    fi
    user="$(sed -n 's/^- Username: //p' <<<"$info")"
    log_info "Proton Pass: logged in as ${user:-<unknown>}"
}

backend_supported_types() {
    printf '%s\n' login password note api_key wifi ssh_key crypto_wallet credit_card identity
}

# backend_find_vault NAME -> prints the vault's share id, or nothing.
backend_find_vault() {
    assert_vault_allowed "$1"
    "$PROTON_CLI" vault list --output json \
        | jq -r --arg name "$1" 'first(.vaults[] | select(.name == $name) | .share_id) // empty'
}

# backend_create_vault NAME -> prints the new vault's share id.
backend_create_vault() {
    assert_vault_allowed "$1"
    "$PROTON_CLI" vault create --name="$1" >/dev/null
    backend_find_vault "$1"
}

# Defence in depth: before the first write, resolve the share id back to its
# vault name and refuse forbidden vaults (e.g. Personal).
_PROTON_ALLOWED_SID=""
_proton_assert_sid_allowed() {
    local sid="$1" name
    [[ "$sid" == "$_PROTON_ALLOWED_SID" ]] && return 0
    name="$("$PROTON_CLI" vault list --output json \
        | jq -r --arg sid "$sid" 'first(.vaults[] | select(.share_id == $sid) | .name) // empty')"
    [[ -n "$name" ]] || die "vault with share id ${sid:0:8}… not found"
    assert_vault_allowed "$name"
    _PROTON_ALLOWED_SID="$sid"
}

# backend_list_titles SHARE_ID -> titles of active items, one per line.
backend_list_titles() {
    "$PROTON_CLI" item list --share-id="$1" --filter-state active --output json \
        | jq -r '.items[].title'
}

# backend_import_entry SHARE_ID PAYLOAD_FILE TMPDIR
# Creates one item. PAYLOAD_FILE is a 0600 file on tmpfs.
backend_import_entry() {
    local sid="$1" payload="$2" tmp="$3" kind title keyfile out
    _proton_assert_sid_allowed "$sid"
    kind="$(jq -r '.kind' "$payload")"
    title="$(jq -r '.template.title' "$payload")"

    case "$kind" in
        login|note|custom|wifi|credit-card|identity)
            out="$(jq '.template' "$payload" \
                | "$PROTON_CLI" item create "$kind" --share-id="$sid" --from-template - 2>&1)" \
                || { log_error "pass-cli: $out"; return 1; }
            ;;
        ssh-key)
            keyfile="$tmp/ssh_key"
            : >"$keyfile"
            chmod 600 "$keyfile"
            jq -j '.private_key' "$payload" >"$keyfile"
            printf '\n' >>"$keyfile"
            out="$("$PROTON_CLI" item create ssh-key import --share-id="$sid" \
                --from-private-key="$keyfile" --title="$title" 2>&1)" \
                || { secure_rm "$keyfile"; log_error "pass-cli: $out"; return 1; }
            secure_rm "$keyfile"
            ;;
        *)
            log_error "unsupported Proton item kind: $kind"
            return 1
            ;;
    esac
    log_debug "pass-cli: created item $(tr '\n' ' ' <<<"$out")"

    if [[ "$(jq -r '.companion != null' "$payload")" == true ]]; then
        _proton_create_companion "$sid" "$payload" || return 1
    fi
}

# Create the companion item (login note + extra fields) of a login.
_proton_create_companion() {
    local sid="$1" payload="$2" title out
    title="$(jq -r '.companion.template.title' "$payload")"
    out="$(jq '.companion.template' "$payload" \
        | "$PROTON_CLI" item create custom --share-id="$sid" --from-template - 2>&1)" || {
        log_error "pass-cli (companion '$title'): $out"
        return 1
    }
    log_info "created custom '$title' (login note and extra fields)"
}
