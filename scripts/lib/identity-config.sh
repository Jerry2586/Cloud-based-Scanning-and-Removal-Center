#!/usr/bin/env bash

appgog_certificate_time() {
  local certificate=${1:?certificate required}
  local field=${2:?certificate date field required}
  local value
  value=$(openssl x509 -in "$certificate" -noout -"$field" | cut -d= -f2-)
  date -u -d "$value" +%Y-%m-%dT%H:%M:%SZ
}

appgog_token_digest() {
  local token_file=${1:?token file required}
  tr -d '\r\n' < "$token_file" | sha256sum | awk '{print $1}'
}

appgog_migrate_token_digests() {
  local config=${1:?config required}
  local work next path digest
  work=$(mktemp "${config}.tokens.XXXXXX")
  next=$(mktemp "${config}.tokens-next.XXXXXX")
  chmod 600 "$work" "$next"
  cp -- "$config" "$work"

  while IFS= read -r path; do
    [[ -n $path ]] || continue
    digest=$(jq -j --argjson path "$path" 'getpath($path).token' "$work" | sha256sum | awk '{print $1}')
    if ! jq --argjson path "$path" --arg digest "$digest" \
      'setpath($path + ["token_sha256"]; $digest) | delpaths([$path + ["token"]])' \
      "$work" > "$next"; then
      rm -f -- "$work" "$next"
      return 1
    fi
    mv -f -- "$next" "$work"
    next=$(mktemp "${config}.tokens-next.XXXXXX")
    chmod 600 "$next"
  done < <(jq -c 'paths(objects) as $path | select((getpath($path).token? | type) == "string") | $path' "$config")

  cat "$work"
  rm -f -- "$work" "$next"
}

appgog_normalize_reader_config() {
  local config=${1:?config required}
  local certificate=${2:?reader certificate required}
  local token_file=${3:?reader token required}
  local fingerprint token_digest issued_at not_after migrated

  [[ -f $config && -f $certificate && -s $token_file ]] || {
    echo 'Reader configuration, certificate, or token is missing' >&2
    return 1
  }
  fingerprint=$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | cut -d= -f2)
  token_digest=$(appgog_token_digest "$token_file")
  issued_at=$(appgog_certificate_time "$certificate" startdate)
  not_after=$(appgog_certificate_time "$certificate" enddate)
  migrated=$(mktemp "${config}.normalized.XXXXXX")
  chmod 600 "$migrated"
  if ! appgog_migrate_token_digests "$config" > "$migrated"; then
    rm -f -- "$migrated"
    return 1
  fi

  if ! jq -e --arg fp "$fingerprint" --arg digest "$token_digest" --arg issued "$issued_at" --arg expires "$not_after" '
    def current_identity:
      {fingerprint256:$fp,token_sha256:$digest,status:"active",issued_at:$issued,cert_not_after:$expires};
    .nodes = (if (.nodes | type) == "object" then .nodes else {} end) |
    .readers = (if (.readers | type) == "array" then .readers else [] end) |
    if (.readers | length) == 0 then .readers = [{role:"reader",identities:[current_identity]}] else . end |
    .readers[0].role = "reader" |
    .readers[0].identities =
      (if (.readers[0].identities | type) == "array" then .readers[0].identities
       elif (.readers[0].fingerprint256 | type) == "string" and (.readers[0].token_sha256 | type) == "string" then
         [{fingerprint256:.readers[0].fingerprint256,token_sha256:.readers[0].token_sha256,status:"active"}]
       else [] end) |
    if any(.readers[0].identities[]; .fingerprint256 == $fp) then
      .readers[0].identities |= map(if .fingerprint256 == $fp then
        .token_sha256 = $digest | del(.token) | .status = "active" | .issued_at = $issued | .cert_not_after = $expires
      else . end)
    elif (.readers[0].identities | length) == 0 then
      .readers[0].identities = [current_identity]
    else error("configured reader identity does not match the local certificate") end |
    del(.readers[0].fingerprint256,.readers[0].token,.readers[0].token_sha256) |
    .policy = (if (.policy | type) == "object" then .policy else {} end) |
    .policy.version = (.policy.version // "1") |
    .policy.rules = (if (.policy.rules | type) == "object" then .policy.rules else {} end) |
    .policy.rules.require_signed_updates = true |
    .policy.rules.allow_remote_commands = false |
    .policy.rules.allow_cloud_push = false
  ' "$migrated"; then
    rm -f -- "$migrated"
    return 1
  fi
  rm -f -- "$migrated"
}
