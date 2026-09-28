# Map a pass-exporter/v1 entry to a Proton Pass (pass-cli) payload:
#   {kind, template, private_key?, companion?, plan_note?}
# kind       -> `pass-cli item create <kind>` (or "ssh-key" for key import)
# template   -> JSON for `--from-template -`
# companion  -> a second item created right after the main one. Used for
#               logins: pass-cli's LoginTemplate cannot hold a note or custom
#               fields, so those go into a custom item "<title>_extras".
# plan_note  -> short, secret-free remark shown in the import plan.

def _nullable: if . == "" then null else . end;
def _footer_only: test("^Imported from pass: [^\n]*$");

def _field($name; $type; $value): {field_name: $name, field_type: $type, value: $value};

# Custom fields from the entry's extra fields.
def _extra_fields:
  [ .fields[]
    | if (.value | test("^otpauth://")) then _field(.name; "totp"; .value)
      elif .sensitive then _field(.name; "hidden"; .value)
      else _field(.name; "text"; .value) end ];

# Standard fields rendered as custom fields (for types that become "custom").
def _standard_fields($secret_name):
  [ (if .username != "" then _field("username"; "text"; .username) else empty end),
    (if .email != ""    then _field("email"; "text"; .email) else empty end),
    (if .password != "" then _field($secret_name; "hidden"; .password) else empty end),
    (.urls[] | _field("url"; "text"; .)),
    (if .totp != ""     then _field("totp"; "totp"; .totp) else empty end) ];

def _custom($section; $secret_name):
  { kind: "custom",
    template: {
      title: .title,
      note: .note,
      sections: [{section_name: $section, fields: (_standard_fields($secret_name) + _extra_fields)}]
                | map(select(.fields | length > 0))
    } };

def _field_value($name): first(.fields[] | select(.name | ascii_downcase == $name) | .value) // null;

def backend_payload:
  if .type == "login" then
    { kind: "login",
      template: {
        title: .title,
        username: (.username | _nullable),
        email: (.email | _nullable),
        password: (.password | _nullable),
        totp_uri: (.totp | _nullable),
        urls: .urls
      },
    }
    + if (.note | _footer_only) and (.fields | length) == 0 then {}
      else
        { companion: {
            kind: "custom",
            template: {
              title: "\(.title)_extras",
              note: "Extra data for login \"\(.title)\"\n\n\(.note)",
              sections: [{section_name: "Extras", fields: _extra_fields}] | map(select(.fields | length > 0))
            } },
          plan_note: "+ \(.title)_extras" }
      end
  elif .type == "note" then
    {kind: "note", template: {title: .title, note: .note}}
  elif .type == "password" then _custom("Credentials"; "password")
  elif .type == "api_key" then _custom("API credential"; "credential")
  elif .type == "crypto_wallet" then _custom("Wallet"; "password")
  elif .type == "wifi" then
    (_field_value("ssid") // .title) as $ssid
    | { kind: "wifi",
        template: {
          title: .title,
          ssid: $ssid,
          password: .password,
          security: (_field_value("security") // "wpa2"),
          note: .note
        } }
  elif .type == "ssh_key" then
    {kind: "ssh-key", template: {title: .title}, private_key: _field_value("private_key")}
  elif .type == "credit_card" then
    { kind: "credit-card",
      template: {
        title: .title,
        cardholder_name: _field_value("cardholder_name"),
        card_type: null,
        number: (_field_value("number") // (.password | _nullable)),
        cvv: _field_value("cvv"),
        expiration_date: _field_value("expiration_date"),
        pin: _field_value("pin"),
        note: .note
      } }
  elif .type == "identity" then
    {kind: "identity", template: {title: .title, note: .note, full_name: .username, email: .email}}
  else
    error("unsupported type: \(.type)")
  end;
