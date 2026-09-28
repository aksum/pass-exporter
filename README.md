# pass-exporter

Exports a [pass](https://www.passwordstore.org/) store to a single, editable JSON
file (`pass-exporter/v1`). You review and edit that file, then an import backend
(Proton Pass first, 1Password later) reads it. Each entry is parsed into
structured fields and classified as a backend-neutral item type.

## Requirements

bash ≥ 4, gpg (with the store's secret key), jq ≥ 1.7, coreutils, iconv, shred, column.
For the Proton Pass import: `pass-cli` (logged in).

## Usage

```bash
./pass-exporter export --dry-run -v   # decrypt + classify, print a table, write nothing
./pass-exporter export                # write ./export/pass-export.json
./pass-exporter summary               # counts per type + entries flagged for review
$EDITOR export/pass-export.json       # review / fix types, titles, fields; set "skip": true
./pass-exporter validate              # check the file after editing
shred -u export/pass-export.json      # when the import is done
```

Options: `-s STORE` (default `$PASSWORD_STORE_DIR`, else `~/.password-store`), `-o FILE`,
`--filter 'Azure/*'`, `--include-raw`, `--keep-going`, `-f/--force`,
`-v/--verbose`, `-q/--quiet`. The `LOG_LEVEL` env var (`error|warn|info|debug`)
and `NO_COLOR` are also honoured.

## Security

- The export file is **cleartext**. It is written with mode `0600` into a `0700`
  directory, gitignored, and the tool refuses to overwrite it without `--force`.
  Delete it with `shred -u` after importing.
- Decrypted entries only exist in a private temp dir on tmpfs (`/dev/shm`).
  They are `shred`ded after each entry and on exit or interrupt.
- Secrets never pass through argv, environment variables or shell variables:
  `gpg → tmpfs file → jq --rawfile`.
- Logs never contain secret values. Debug output shows only paths, types,
  rules, which standard fields are set, and a *count* of extra fields. Field
  names are not logged because they come from the secret content itself.
- `umask 077`, no core dumps, and `set -x` is never used.
- The file is built in a temp file and moved into place atomically, so a
  failed or interrupted run leaves nothing behind. If any entry fails to
  decrypt, nothing is written (unless `--keep-going`).

## Export format (`pass-exporter/v1`)

```json
{
  "format": "pass-exporter/v1",
  "exported_at": "…", "source": {"store": "…", "gpg_id": "…", "count": 103},
  "entries": [{
    "id": "3f2a…",                       // sha256(path)[0:12], stable across runs
    "source_path": "Azure/user/pedro.gomes@olisto.com",
    "type": "login",                     // editable
    "classification": {"rule": "login.basename-email", "confidence": "high", "review": false},
    "skip": false,                       // set true to leave the entry out of the import
    "title": "azure_user_pedro.gomes@olisto.com",  // path segments joined with "_", lowercased, spaces -> "_"
    "username": "…", "email": "…", "password": "…", "urls": [], "totp": "",
    "note": "…\n\nImported from pass: Azure/user/pedro.gomes@olisto.com",
    "fields": [{"name": "tenant_id", "value": "…", "sensitive": false}],
    "tags": ["pass-import", "Azure", "user"],
    "encoding": "utf8"                   // "base64" for binary entries (content in note)
  }]
}
```

### Parsing (pass/browserpass conventions)

- Line 1 is the password. The exception is when line 1 is itself `user: …` or
  similar; then every line is parsed as structured data.
- `user|username|login`, `email`, `url|website`, `otp|totp` and `password` keys
  map to the standard fields. Any other `key: value` becomes a custom field.
  A field is `sensitive` if its name looks secret.
- An `otpauth://…` line goes to `totp`. A bare `https://…` line goes to `urls`.
  Every other line is kept in `note`.
- PEM/PGP blobs, notes and seed phrases are kept verbatim.

### Types and classification rules (first match wins)

| type | examples / rule ids |
|---|---|
| `note` | `binary`, `pem.other` (CSR/cert/key), `pgp.armor`, `path.recovery-code`, `unstructured` |
| `ssh_key` | `pem.openssh-private-key`, `pem.ssh-private-key` |
| `wifi` | `path.ssid` (`…/SSID/<name>`, ssid field = basename) |
| `crypto_wallet` | `path.crypto-top` (`Monero/`, `ZCASH/`), `seed-phrase` |
| `api_key` | `path.api-credential` (token, apikey, secret, webhook, `Azure/SP/`, `AKIA…`) |
| `login` | `login.fields`, `login.parent-user` (`…/<user>/psw`), `login.basename-email`, `login.user-folder`, `login.basename-user` |
| `password` | `path.encryption-secret` (repo/restic/tomb/e2ee/radius), `path.secret-name` (`…/key`), `single-secret` |

Entries with `review: true` are low-confidence guesses. `summary` lists them.

## Tests

```bash
tests/run.sh           # throwaway GnuPG home + fixture store, golden compare, leak & cleanup checks
tests/run.sh --update  # regenerate tests/expected.json after an intended change
```

## Import

```bash
./pass-exporter import --backend proton                  # dry run: prints the plan, creates nothing
./pass-exporter import --backend proton --apply          # asks for confirmation, then creates items
./pass-exporter import --backend proton --filter 'Azure/*' --vault work-import --apply
```

- Everything goes into **one** vault: `--vault NAME`, default **`pass-exporter`**.
  It is created if it doesn't exist.
- The **`Personal`** vault (any capitalisation) is **never** used. The driver
  refuses it before contacting the backend. The Proton backend also resolves
  the target vault's ID back to its name before the first write, and refuses
  if that is `Personal`.
- Entries whose title already exists in the target vault are skipped, so a
  re-run only creates what is missing. Entries with `"skip": true` are ignored.
- Use `--yes` for non-interactive runs and `--delay SECONDS` if the API
  throttles you.
- Proton Pass needs a logged-in `pass-cli` (`pass-cli login`).

See [backends/README.md](backends/README.md) for the backend contract, the
Proton Pass type mapping (including the `<title>_extras` companion items for
logins with notes/fields), and notes for the planned 1Password backend.
