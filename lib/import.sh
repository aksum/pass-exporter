# shellcheck shell=bash
# Backend-agnostic import driver: validates the export file, loads
# backends/<name>.sh + backends/<name>.jq, skips existing titles, and creates
# items in ONE target vault (dry run unless --apply). Requires log.sh and common.sh.
#
# Globals used: OUTPUT BACKEND VAULT FILTER APPLY ASSUME_YES DELAY SCRIPT_DIR
# shellcheck disable=SC2153 # the globals above are set by pass-exporter

readonly DEFAULT_IMPORT_VAULT="pass-exporter"

# Vaults that must never receive imported items (compared case-insensitively,
# ignoring surrounding whitespace). "Personal" is Proton Pass's default vault.
readonly FORBIDDEN_VAULTS=(personal)

# assert_vault_allowed NAME — die if NAME is empty or forbidden.
assert_vault_allowed() {
    local name="$1" norm forbidden
    norm="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -n "$norm" ]] || die "no import vault given (use --vault NAME; default: $DEFAULT_IMPORT_VAULT)"
    for forbidden in "${FORBIDDEN_VAULTS[@]}"; do
        [[ "$norm" != "$forbidden" ]] \
            || die "refusing to import into vault '$name': the '$forbidden' vault is never used for imports"
    done
}

# _import_plan NAME -> TSV rows: index, path, type, kind, title, plan_note
# Never contains secret values.
_import_plan() {
    local name="$1"
    jq -r -L "$SCRIPT_DIR/backends" \
        --rawfile supported "$IMPORT_TMP/supported" \
        "include \"$name\";"'
        ($supported | split("\n") | map(select(. != ""))) as $types
        | .entries | to_entries[]
        | .key as $i | .value as $e
        | ($e | backend_payload? // {kind: "-"}) as $p
        | [ $i, $e.source_path, $e.type,
            (if $e.skip then "skip"
             elif ($e.type | IN($types[]) | not) then "unsupported"
             else $p.kind end),
            $e.title,
            ($p.plan_note // "-") ]
        | @tsv' "$OUTPUT" \
        | while IFS=$'\t' read -r i path type kind title note; do
            # --filter is a shell glob on source_path.
            # shellcheck disable=SC2053
            if [[ -n "$FILTER" && "$path" != $FILTER ]]; then continue; fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$path" "$type" "$kind" "$title" "$note"
        done
}

# _import_with_retry SID PAYLOAD TITLE — up to 3 attempts with backoff
# (API throttling, network). Before retrying, re-check the vault so an attempt
# that succeeded server-side but reported an error is not duplicated.
_import_with_retry() {
    local sid="$1" payload="$2" title="$3" attempt=1 delay=2
    until backend_import_entry "$sid" "$payload" "$IMPORT_TMP"; do
        (( attempt >= 3 )) && return 1
        log_warn "attempt $attempt failed, retrying in ${delay}s"
        sleep "$delay"
        if backend_list_titles "$sid" | grep -qxF -- "$title"; then
            log_error "'$title' was created but the import reported an error; check it (and any companion item) in the vault"
            return 1
        fi
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done
}

_confirm_apply() {
    local n="$1" reply
    [[ "$ASSUME_YES" == true ]] && return 0
    [[ -t 0 ]] || die "refusing to import without confirmation; pass --yes for non-interactive use"
    printf "Create %s items in %s vault '%s'. Continue? [y/N] " "$n" "$BACKEND" "$VAULT" >&2
    read -r reply
    [[ "$reply" == y || "$reply" == Y || "$reply" == yes ]] || die "aborted"
}

cmd_import() {
    [[ -n "$BACKEND" ]] || die "--backend is required (available: $(find "$SCRIPT_DIR/backends" -maxdepth 1 -name '*.sh' -printf '%f ' | sed 's/\.sh / /g'))"
    [[ "$BACKEND" =~ ^[a-z0-9_-]+$ ]] || die "invalid backend name: $BACKEND"
    [[ -f "$SCRIPT_DIR/backends/$BACKEND.sh" && -f "$SCRIPT_DIR/backends/$BACKEND.jq" ]] \
        || die "unknown backend: $BACKEND (expected backends/$BACKEND.sh and backends/$BACKEND.jq)"
    VAULT="${VAULT:-$DEFAULT_IMPORT_VAULT}"
    assert_vault_allowed "$VAULT"

    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/backends/$BACKEND.sh"

    cmd_validate
    backend_check_deps
    backend_check_auth

    make_secure_tmpdir
    IMPORT_TMP="$SECURE_TMPDIR"
    backend_supported_types >"$IMPORT_TMP/supported"

    local plan="$IMPORT_TMP/plan.tsv"
    _import_plan "$BACKEND" >"$plan"
    # shellcheck disable=SC2016 # literal quotes around the glob
    [[ -s "$plan" ]] || die "no entries selected${FILTER:+ by filter '$FILTER'}"

    # Resolve the target vault and fetch existing titles (read-only).
    local sid titles="$IMPORT_TMP/titles"
    sid="$(backend_find_vault "$VAULT")"
    if [[ -n "$sid" ]]; then
        backend_list_titles "$sid" >"$titles"
        log_info "target vault '$VAULT' exists ($(wc -l <"$titles") items)"
    else
        : >"$titles"
        log_info "target vault '$VAULT' does not exist yet; it will be created"
    fi

    # Decide per entry: create / exists / skip / unsupported.
    local i path type kind title note action decided="$IMPORT_TMP/decided.tsv"
    local n_create=0 n_exists=0 n_skip=0 n_unsup=0
    : >"$decided"
    while IFS=$'\t' read -r i path type kind title note; do
        if [[ "$kind" == skip ]]; then
            action=skip; n_skip=$((n_skip + 1))
        elif [[ "$kind" == unsupported ]]; then
            action=unsupported; n_unsup=$((n_unsup + 1))
        elif grep -qxF -- "$title" "$titles"; then
            action=exists; n_exists=$((n_exists + 1))
        else
            action=create; n_create=$((n_create + 1))
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$path" "$type" "$kind" "$title" "$note" "$action" >>"$decided"
    done <"$plan"

    {
        printf 'PATH\tTYPE\tITEM\tTITLE\tACTION\tNOTE\n'
        awk -F'\t' '{ printf "%s\t%s\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5, $7, $6 }' "$decided"
    } | column -t -s $'\t'
    log_info "plan for vault '$VAULT': create=$n_create exists=$n_exists skip=$n_skip unsupported=$n_unsup"

    if [[ "$APPLY" != true ]]; then
        log_info "dry run: nothing imported (add --apply to import)"
        return 0
    fi
    (( n_create > 0 )) || { log_info "nothing to import"; return 0; }
    _confirm_apply "$n_create"

    if [[ -z "$sid" ]]; then
        sid="$(backend_create_vault "$VAULT")"
        [[ -n "$sid" ]] || die "could not create vault '$VAULT'"
        log_info "created vault '$VAULT'"
    fi

    local payload="$IMPORT_TMP/payload.json" n_ok=0 n_fail=0
    while IFS=$'\t' read -r i path type kind title note action; do
        [[ "$action" == create ]] || continue
        : >"$payload"
        chmod 600 "$payload"
        jq -L "$SCRIPT_DIR/backends" --argjson i "$i" \
            "include \"$BACKEND\"; .entries[\$i] | backend_payload" "$OUTPUT" >"$payload"
        if _import_with_retry "$sid" "$payload" "$title"; then
            n_ok=$((n_ok + 1))
            printf '%s\n' "$title" >>"$titles"
            log_info "created $kind '$title' ($path)"
        else
            n_fail=$((n_fail + 1))
            log_error "failed to import $path"
        fi
        secure_rm "$payload"
        [[ "$DELAY" == 0 ]] || sleep "$DELAY"
    done <"$decided"

    log_info "import into '$VAULT' done: created=$n_ok failed=$n_fail exists=$n_exists skip=$n_skip unsupported=$n_unsup"
    (( n_fail == 0 )) || die "$n_fail entries failed; re-run the same command to retry (existing titles are skipped)"
}
