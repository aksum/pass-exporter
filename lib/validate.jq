# Validate a pass-exporter/v1 file. Outputs a list of error strings
# (empty array = valid). Never echoes secret values.

def _types: ["login", "password", "note", "api_key", "wifi", "ssh_key",
             "crypto_wallet", "credit_card", "identity"];
def _required: ["id", "source_path", "type", "skip", "title", "username",
                "email", "password", "urls", "totp", "note", "fields", "tags", "encoding"];

def validate:
  [
    (if .format != "pass-exporter/v1" then "unsupported format: \(.format // "missing")" else empty end),
    (if (.entries | type) != "array" then "entries must be an array" else empty end),
    ( (.entries // [])
      | ( [.[].id] | group_by(.) | map(select(length > 1) | "duplicate id: \(.[0])") | .[] ),
        ( to_entries[] | .key as $i | .value as $e
          | ($e.source_path // "#\($i)") as $ref
          | ( (_required - ($e | keys)) | select(length > 0) | "\($ref): missing keys \(join(", "))" ),
            ( if ($e.type | IN(_types[])) then empty else "\($ref): unknown type \($e.type)" end ),
            ( if ($e.skip | type) != "boolean" then "\($ref): skip must be boolean" else empty end ),
            ( if ($e.title // "" | test("\\S")) then empty else "\($ref): empty title" end ),
            ( if ($e.urls | type) != "array" then "\($ref): urls must be an array" else empty end ),
            ( if ($e.fields | type) != "array" then "\($ref): fields must be an array"
              elif any($e.fields[]; (.name | type) != "string" or (.value | type) != "string")
              then "\($ref): every field needs string name and value" else empty end ),
            ( if $e.skip != true and ($e.type | IN("login", "password")) and (($e.password // "") == "")
              then "\($ref): \($e.type) without password" else empty end )
        )
    )
  ];
