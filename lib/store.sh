# shellcheck shell=bash
# pass (password-store) source: preflight, enumeration, decryption.

# store_preflight STORE_DIR
# Validates the store and that at least one recipient secret key is usable.
store_preflight() {
    local store="$1" gpg_id info expired
    [[ -d "$store" ]] || die "store not found: $store"
    [[ -f "$store/.gpg-id" ]] || die "not a pass store (no .gpg-id): $store"

    while IFS= read -r gpg_id || [[ -n "$gpg_id" ]]; do
        gpg_id="${gpg_id%%#*}"
        gpg_id="${gpg_id//[[:space:]]/}"
        [[ -n "$gpg_id" ]] || continue
        if ! info="$(gpg --batch --with-colons --list-secret-keys -- "$gpg_id" 2>/dev/null)"; then
            log_warn "no secret key for recipient $gpg_id in keyring"
            continue
        fi
        expired="$(awk -F: '$1=="sec" && $2=="e" {print "yes"}' <<<"$info")"
        if [[ "$expired" == yes ]]; then
            log_warn "secret key $gpg_id is expired (decryption still works)"
        else
            log_debug "secret key $gpg_id available"
        fi
        return 0
    done <"$store/.gpg-id"
    die "none of the recipients in $store/.gpg-id has a secret key in this keyring"
}

# store_first_gpg_id STORE_DIR
store_first_gpg_id() {
    grep -v '^[[:space:]]*\(#\|$\)' "$1/.gpg-id" | head -n1 | tr -d '[:space:]'
}

# store_list_entries STORE_DIR [GLOB]
# Prints entry names (path relative to store, without .gpg), NUL-delimited, sorted.
store_list_entries() {
    local store="$1" filter="${2:-}" f rel
    while IFS= read -r -d '' f; do
        rel="${f#"$store"/}"
        rel="${rel%.gpg}"
        # shellcheck disable=SC2053 # intentional glob match
        if [[ -n "$filter" && "$rel" != $filter ]]; then
            continue
        fi
        printf '%s\0' "$rel"
    done < <(find "$store" \
        \( -name .git -o -name .public-keys -o -name .extensions \) -prune -o \
        -type f -name '*.gpg' -print0 | sort -z)
}

# store_decrypt_to STORE_DIR ENTRY OUT_FILE
# Decrypts one entry into OUT_FILE (created 0600 by umask). Secrets never
# touch argv, environment, or shell variables.
store_decrypt_to() {
    local store="$1" entry="$2" out="$3"
    : >"$out"
    chmod 600 "$out"
    gpg --quiet --batch --yes --decrypt -- "$store/$entry.gpg" >"$out" 2>"$out.err" || {
        log_error "gpg failed for $entry: $(tr '\n' ' ' <"$out.err")"
        secure_rm "$out" "$out.err"
        return 1
    }
    rm -f -- "$out.err"
}

# is_utf8_text FILE — true if valid UTF-8 without NUL bytes.
is_utf8_text() {
    iconv -f UTF-8 -t UTF-8 -- "$1" >/dev/null 2>&1 || return 1
    ! LC_ALL=C grep -qaP '\x00' -- "$1"
}
