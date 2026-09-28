# shellcheck shell=bash
# Shared runtime: hardening, dependency checks, secure temp dir, cleanup.
# Requires lib/log.sh to be sourced first.

die() {
    local IFS=' '
    log_error "$*"
    exit 1
}

# Harden the process. Called once from the entry point.
harden() {
    umask 077
    ulimit -c 0 2>/dev/null || true # no core dumps containing secrets
    export LC_ALL=C.UTF-8
}

require_bash() {
    (( BASH_VERSINFO[0] >= 4 )) || die "bash >= 4 required (found ${BASH_VERSION})"
}

require_cmds() {
    local cmd missing=() IFS=' '
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    (( ${#missing[@]} == 0 )) || die "missing required commands: ${missing[*]}"
    log_debug "dependencies OK: $*"
}

# Securely remove a file: shred when possible, plain rm as fallback.
secure_rm() {
    local f
    for f in "$@"; do
        [[ -e "$f" ]] || continue
        shred -u -z -- "$f" 2>/dev/null || rm -f -- "$f"
    done
}

# Files/dirs to wipe on exit. Registered through register_cleanup.
_CLEANUP_FILES=()
_CLEANUP_DIRS=()

register_cleanup_file() { _CLEANUP_FILES+=("$1"); }
register_cleanup_dir()  { _CLEANUP_DIRS+=("$1"); }

cleanup() {
    local rc=$? d f
    trap - EXIT INT TERM
    for f in "${_CLEANUP_FILES[@]}"; do
        secure_rm "$f"
    done
    for d in "${_CLEANUP_DIRS[@]}"; do
        [[ -d "$d" ]] || continue
        while IFS= read -r -d '' f; do
            secure_rm "$f"
        done < <(find "$d" -type f -print0 2>/dev/null)
        rm -rf -- "$d"
        log_debug "removed temp dir $d"
    done
    exit "$rc"
}

on_signal() {
    log_warn "interrupted, cleaning up"
    exit 130
}

install_traps() {
    trap cleanup EXIT
    trap on_signal INT TERM
}

# Create a private (0700) temp dir, preferring RAM-backed storage.
# Sets the global SECURE_TMPDIR (not via $(...) so cleanup registration sticks).
SECURE_TMPDIR=''
make_secure_tmpdir() {
    local base dir
    for base in /dev/shm "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-/tmp}"; do
        [[ -n "$base" && -d "$base" && -w "$base" ]] || continue
        dir="$(mktemp -d "$base/pass-exporter.XXXXXXXX")" || continue
        chmod 700 "$dir"
        [[ "$base" == /dev/shm || "$base" == "${XDG_RUNTIME_DIR:-}" ]] \
            || log_warn "no tmpfs available, using $base for temporary decrypted data"
        register_cleanup_dir "$dir"
        log_debug "temp dir: $dir"
        # shellcheck disable=SC2034 # read by the caller
        SECURE_TMPDIR="$dir"
        return 0
    done
    die "could not create a temporary directory"
}
