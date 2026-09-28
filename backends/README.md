# Import backends

A backend creates items in a password manager from a `pass-exporter/v1` file.
It is driven by `./pass-exporter import --backend <name>` ([lib/import.sh](../lib/import.sh)).

| backend | status |
|---|---|
| `proton` | done: Proton Pass through `pass-cli` |
| `1password` | planned: `op item create` |

## Contract

A backend is two files:

**`backends/<name>.jq`** defines `backend_payload`. It turns one v1 entry
into a payload object:

| key | meaning |
|---|---|
| `kind` | backend item kind; shown in the plan |
| `template` | what gets created; must contain `title` |
| `companion` | optional second item, created right after the main one |
| `plan_note` | optional short, **secret-free** remark shown in the plan |

**`backends/<name>.sh`** defines these shell functions:

| function | purpose |
|---|---|
| `backend_check_deps` | verify the CLI tools exist |
| `backend_check_auth` | verify there is a logged-in session; `die` with a hint if not |
| `backend_supported_types` | internal types it can import, one per line |
| `backend_find_vault NAME` | print the vault's id, or nothing if it doesn't exist |
| `backend_create_vault NAME` | create the vault and print its id |
| `backend_list_titles VAULT_ID` | titles of active items, one per line (used to skip duplicates) |
| `backend_import_entry VAULT_ID PAYLOAD_FILE TMPDIR` | create the item (and companion); non-zero on failure |

The driver handles the rest:
1. Validates the file.
2. Applies `--filter` and `skip: true`.
3. Resolves the single target vault (`--vault`, default `pass-exporter`).
   It refuses forbidden vaults (`Personal`) via `assert_vault_allowed`
   before any backend call.
4. Skips titles that already exist.
5. Prints the plan and stays a **dry run unless `--apply`**, asking for
   confirmation unless `--yes` is given.
6. Writes each payload to a `0600` file on tmpfs and shreds it afterwards.
7. Retries failures up to 3 times with backoff. Before each retry it re-checks
   the vault, so an item that was created despite an error is not duplicated.

Rules for backends:
- Call `assert_vault_allowed NAME` for any vault name you resolve or create,
  and re-check the vault behind the id before writing. Never import into
  `Personal`.
- Secrets go to the tool on **stdin** or in a `0600` tmpfs file. Never on argv
  or in environment variables.
- Log titles, kinds and ids only.

## Proton Pass (`proton`)

The backend uses `pass-cli item create <kind> --share-id <vault> --from-template -`,
with the template on stdin.

| internal type | Proton item | notes |
|---|---|---|
| `login` | login | username, email, password, urls, TOTP. See *login extras* below |
| `password` | custom | section "Credentials": hidden `password` field (+ username/email if set) |
| `note` | note | full content verbatim |
| `api_key` | custom | section "API credential": hidden `credential` field + extra fields |
| `crypto_wallet` | custom | section "Wallet": hidden `password` / `recovery_phrase` + extra fields |
| `wifi` | wifi | ssid from the `ssid` field (or the title), security `wpa2` unless a `security` field says otherwise |
| `ssh_key` | ssh-key | `item create ssh-key import --from-private-key <0600 tmpfs file>` |
| `credit_card` | credit-card | from fields `cardholder_name`, `number`, `cvv`, `expiration_date`, `pin` |
| `identity` | identity | name/email only |

In custom items, extra fields become `hidden` when `sensitive` is true,
`totp` for `otpauth://` values, and `text` otherwise. Custom items and notes
keep the entry's note, including the `Imported from pass: <path>` line.

**Login extras.** `pass-cli`'s login template has no note or custom fields (it
silently drops a `note` key). `item update --field` could add them, but it
takes values on argv and only makes plain-text fields. So a login with a note
or extra fields gets a companion **custom item `<title>_extras`** holding the
note and fields, with secret fields hidden. The login itself keeps autofill.

Behaviour verified against pass-cli 2.4.1:
- `vault create` and `item create` print the new id.
- `item list --output json` returns titles without secrets (unless
  `--show-secrets` is given).
- `pass-cli` refuses to run while `~/.local/share/proton-pass-cli/.session` is
  group/world accessible. Fix with `chmod 700` on that folder.

## 1Password (planned)

Use `op item create --category <cat> --vault <vault> --template <file>`, with
the template in a `0600` tmpfs file. Categories: Login, Password, Secure Note,
API Credential, Wireless Router, SSH Key, Crypto Wallet, Credit Card,
Identity. 1Password logins support notes and custom fields directly, so no
companion item is needed.
