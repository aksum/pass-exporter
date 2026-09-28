# Classify a parsed pass entry into a backend-neutral item type and build the
# final export entry (pass-exporter/v1).
#
# Types: login, password, note, api_key, wifi, ssh_key, crypto_wallet,
#        credit_card, identity
# First matching rule wins; the rule id is recorded for review.

include "parse";

def _seed_phrase: test("^\\s*([a-z]+\\s+){11,23}[a-z]+\\s*$");
def _looks_email: test("^[^@\\s/]+@[^@\\s/]+\\.[A-Za-z]{2,}$");
def _looks_user:  test("^[A-Za-z0-9][A-Za-z0-9._@+-]{1,63}$") and (test("^[0-9a-fA-F]{24,}$") | not);

def _result($type; $rule; $conf; $review):
  {type: $type, rule: $rule, confidence: $conf, review: $review};

# Input: {path, parsed, encoding}. Output: classification result.
def classify:
  .path as $path
  | .parsed as $p
  | ($path | split("/")) as $segs
  | ($segs[-1]) as $base
  | ($base | ascii_downcase) as $lbase
  | ($path | ascii_downcase) as $lpath
  | ($segs | map(ascii_downcase)) as $lsegs
  | ($p.content // "") as $c
  | if .encoding == "base64" then
      _result("note"; "binary"; "low"; true)
    elif $p.blob and ($c | test("-----BEGIN OPENSSH PRIVATE KEY-----")) then
      _result("ssh_key"; "pem.openssh-private-key"; "high"; false)
    elif $p.blob and ($c | test("-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----")) and ($lpath | test("ssh")) then
      _result("ssh_key"; "pem.ssh-private-key"; "medium"; false)
    elif $p.blob and ($c | test("-----BEGIN PGP ")) then
      _result("note"; "pgp.armor"; "high"; false)
    elif $p.blob then
      _result("note"; "pem.other"; "high"; false)
    elif ($c | test("-----BEGIN [A-Z ]+-----")) then
      _result("note"; "pem.embedded"; "medium"; true)
    elif ($lsegs | any(. == "ssid" or . == "wifi" or . == "wlan")) then
      _result("wifi"; "path.ssid"; "high"; false)
    elif ($lsegs[0] | IN("monero", "zcash", "bitcoin", "ethereum", "wallet")) then
      _result("crypto_wallet"; "path.crypto-top"; "high"; ($lbase == "address"))
    elif ($lbase | test("^(seed|mnemonic|wallet)$")) or ($p.password | _seed_phrase) then
      _result("crypto_wallet"; "seed-phrase"; "medium"; true)
    elif ($lbase | test("^(recovery|recover|backup)[-_ ]?codes?$")) then
      _result("note"; "path.recovery-code"; "high"; false)
    elif ($lpath | test("token|api[-_]?key|apitoken|secret|vault_key|config_key|webhook|(^|/)keys$|(^|/)sp/"))
         or ($c | test("AKIA[0-9A-Z]{16}")) then
      _result("api_key"; "path.api-credential"; "high"; false)
    elif ($lsegs[:-1] | any(IN("user", "users", "account", "accounts"))) and ($base | _looks_user) then
      _result("login"; "login.user-folder"; "high"; false)
    elif ($lsegs[:-1] | any(IN("repo", "repos", "repository", "tomb", "restic", "luks", "e2ee",
                                "encryption", "passphrase", "radius"))) then
      _result("password"; "path.encryption-secret"; "medium"; true)
    elif ($lbase | IN("key", "secret", "secret-key", "secretkey", "master-key", "masterkey", "pin", "passphrase")) then
      _result("password"; "path.secret-name"; "medium"; true)
    elif $p.username != "" or $p.email != "" then
      _result("login"; "login.fields"; "high"; false)
    elif ($lbase | IN("psw", "pass", "password", "pwd", "login")) and ($segs | length) >= 3 then
      _result("login"; "login.parent-user"; "high"; false)
    elif ($base | _looks_email) then
      _result("login"; "login.basename-email"; "high"; false)
    elif ($base | _looks_user) and $p.line_count <= 3 then
      _result("login"; "login.basename-user"; "medium"; false)
    elif $p.line_count == 1 then
      _result("password"; "single-secret"; "low"; true)
    else
      _result("note"; "unstructured"; "low"; true)
    end;

def _footer($path): "Imported from pass: \($path)";

def _join_note($lines; $path):
  ($lines | join("\n")) as $body
  | if $body == "" then _footer($path) else "\($body)\n\n\(_footer($path))" end;

# Build the final export entry.
# $content: raw text (or base64 when $encoding == "base64")
def build_entry($content; $path; $id; $encoding; $include_raw):
  ($path | split("/")) as $segs
  | (if $encoding == "base64" then {blob: true, password: "", username: "", email: "",
       urls: [], totp: "", fields: [], note_lines: [], line_count: 0, content: ""}
     else $content | parse_content end) as $p
  | ({path: $path, parsed: $p, encoding: $encoding} | classify) as $cls
  | {
      id: $id,
      source_path: $path,
      type: $cls.type,
      classification: {rule: $cls.rule, confidence: $cls.confidence, review: $cls.review},
      skip: false,
      title: ($segs | join("_") | ascii_downcase | gsub("\\s+"; "_")),
      username: $p.username,
      email: $p.email,
      password: $p.password,
      urls: ($p.urls | unique),
      totp: $p.totp,
      note: _join_note($p.note_lines; $path),
      fields: $p.fields,
      tags: (["pass-import"] + $segs[:-1]),
      encoding: $encoding
    }
  # Type-specific finishing touches.
  | if .type == "note" then
      # Notes carry the whole secret verbatim in the note body.
      (if $encoding == "base64" then $content else $p.content end) as $body
      | .note = "\($body)\n\n\(_footer($path))"
      | .password = "" | .username = "" | .email = "" | .totp = "" | .urls = [] | .fields = []
    elif .type == "ssh_key" then
      .fields = [{name: "private_key", value: $p.content, sensitive: true}]
      | .note = _footer($path) | .password = ""
    elif .type == "wifi" then
      if any(.fields[]; .name | ascii_downcase == "ssid") then .
      else .fields = [{name: "ssid", value: $segs[-1], sensitive: false}] + .fields end
    elif .type == "crypto_wallet" and ($segs[-1] | ascii_downcase | test("^(seed|mnemonic)$")) then
      # Keep a seed verbatim: its lines must not be split into "key: value" fields.
      .fields = [{name: "recovery_phrase", value: $p.content, sensitive: true}]
      | .password = "" | .note = _footer($path)
    elif .type == "crypto_wallet" and (.password | _seed_phrase) then
      .fields = [{name: "recovery_phrase", value: .password, sensitive: true}] + .fields
      | .password = ""
    elif .type == "login" and .username == "" then
      (if $cls.rule == "login.parent-user" then $segs[-2] else $segs[-1] end) as $u
      | .username = $u
      | if .email == "" and ($u | _looks_email) then .email = $u
        elif .email == "" and ($segs | length) >= 3 and ($segs[-2] | _looks_email) then .email = $segs[-2]
        else . end
    else . end
  | if $include_raw then .raw = $content else . end;
