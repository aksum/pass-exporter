# Parse the decrypted content of one pass entry into structured fields.
#
# Follows the pass / browserpass conventions:
#   line 1           -> password
#   "key: value"     -> username / email / url / totp / custom field
#   otpauth://...    -> totp
#   https://...      -> url
#   anything else    -> note (nothing is dropped)
# A PEM/PGP blob (first line "-----BEGIN ...") is kept whole as note.

def _trim: sub("^\\s+"; "") | sub("\\s+$"; "");

def _key_map:
  ascii_downcase | _trim
  | if test("^(user|username|user name|login|account)$") then "username"
    elif test("^(email|e-mail|mail)$") then "email"
    elif test("^(url|urls|uri|website|site|link|web)$") then "url"
    elif test("^(otp|totp|2fa|mfa)$") then "totp"
    elif test("^(password|pass|pwd|psw)$") then "password"
    else null end;

def _is_sensitive_key:
  test("secret|key|token|pin|code|pass|pwd|psw|seed|private|phrase|otp|recover|backup"; "i");

# "key: value" -> {k, v} or null
def _kv:
  if test("^\\s*[A-Za-z][A-Za-z0-9 _.-]{0,40}\\s*:")
  then capture("^\\s*(?<k>[A-Za-z][A-Za-z0-9 _.-]{0,40}?)\\s*:\\s*(?<v>.*?)\\s*$")
       | if (.k | ascii_downcase | IN("http", "https", "otpauth", "ftp", "ssh")) then null else . end
  else null end;

def _apply_line($l):
  ($l | _kv) as $kv
  | if ($l | test("^\\s*otpauth://")) then
      if .totp == "" then .totp = ($l | _trim)
      else .fields += [{name: "otpauth", value: ($l | _trim), sensitive: true}] end
    elif ($l | test("^\\s*https?://\\S+\\s*$")) then .urls += [$l | _trim]
    elif $kv != null then
      ($kv.k | _key_map) as $m
      | if   $m == "username" and .username == "" then .username = $kv.v
        elif $m == "email"    and .email == ""    then .email = $kv.v
        elif $m == "url"      and $kv.v != ""     then .urls += [$kv.v]
        elif $m == "totp"     and .totp == ""     then .totp = $kv.v
        elif $m == "password" and .password == "" then .password = $kv.v
        else .fields += [{name: ($kv.k | _trim), value: $kv.v, sensitive: ($kv.k | _is_sensitive_key)}] end
    else .note_lines += [$l] end;

# Drop leading and trailing blank lines from an array of lines.
def _strip_blank_edges:
  until(length == 0 or (.[0] | test("\\S")); .[1:])
  | until(length == 0 or (.[-1] | test("\\S")); .[:-1]);

# Input: raw content string. Output: parsed object.
def parse_content:
  gsub("\r\n"; "\n")
  | sub("\n+$"; "") as $c
  | ($c | split("\n")) as $lines
  | {
      blob: false, password: "", username: "", email: "", urls: [], totp: "",
      fields: [], note_lines: [], line_count: ($lines | length), content: $c
    }
  | if ($c | test("^\\s*-----BEGIN ")) then
      .blob = true | .note_lines = $lines
    else
      # If line 1 is itself a known "key: value" (e.g. "user: x"), there is no
      # bare password line; parse every line as structured data.
      (($lines[0] // "") | _kv) as $first
      | if $first != null and ($first.k | _key_map) != null then
          reduce $lines[] as $l (.; _apply_line($l))
        else
          .password = ($lines[0] // "")
          | reduce $lines[1:][] as $l (.; _apply_line($l))
        end
    end
  | .note_lines |= _strip_blank_edges;
