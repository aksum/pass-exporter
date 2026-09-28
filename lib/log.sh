# shellcheck shell=bash
# Logging helpers. All output goes to stderr so stdout stays clean for data.
# NEVER pass secret values to these functions: log paths, types, field names
# and counts only.

# Levels: error=0 warn=1 info=2 debug=3
LOG_LEVEL="${LOG_LEVEL:-info}"

_log_level_num() {
    case "$1" in
        error) echo 0 ;;
        warn|warning) echo 1 ;;
        info) echo 2 ;;
        debug) echo 3 ;;
        *) echo 2 ;;
    esac
}

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    _LOG_C_ERR=$'\e[31m' _LOG_C_WARN=$'\e[33m' _LOG_C_INFO=$'\e[32m'
    _LOG_C_DEBUG=$'\e[2m' _LOG_C_RESET=$'\e[0m'
else
    _LOG_C_ERR='' _LOG_C_WARN='' _LOG_C_INFO='' _LOG_C_DEBUG='' _LOG_C_RESET=''
fi

_log() {
    local level="$1" color="$2" IFS=' '
    shift 2
    (( $(_log_level_num "$level") <= $(_log_level_num "$LOG_LEVEL") )) || return 0
    printf '%s%s [%-5s] %s%s\n' "$color" "$(date +%H:%M:%S)" "${level^^}" "$*" "$_LOG_C_RESET" >&2
}

log_error() { _log error "$_LOG_C_ERR" "$@"; }
log_warn()  { _log warn  "$_LOG_C_WARN" "$@"; }
log_info()  { _log info  "$_LOG_C_INFO" "$@"; }
log_debug() { _log debug "$_LOG_C_DEBUG" "$@"; }
