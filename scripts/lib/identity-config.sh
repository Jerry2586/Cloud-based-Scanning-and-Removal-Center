#!/usr/bin/env bash

appgog_certificate_time() {
  local certificate=${1:?certificate required}
  local field=${2:?certificate date field required}
  local value
  value=$(openssl x509 -in "$certificate" -noout -"$field" | cut -d= -f2-)
  date -u -d "$value" +%Y-%m-%dT%H:%M:%SZ
}

appgog_normalize_reader_config() {
  local config=${1:?config required}
  local certificate=${2:?reader certificate required}
  local token_file=${3:?reader token required}
  local fingerprint token issued_at not_after

  [[ -f $config && -f $certificate && -s $token_file ]] || {
    echo 'Reader configuration, certificate, or token is missing' >&2
    return 1
  }
  fingerprint=$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | cut -d= -f2)
  token=$(cat "$token_file")
  issued_at=$(appgog_certificate_time "$certificate" startdate)
  not_after=$(appgog_certificate_time "$certificate" enddate)

  jq -e --arg fp "$fingerprint" --arg token "$token" --arg issued "$issued_at" --arg expires "$not_after" '
    def current_identity:
      {fingerprint256:$fp,token:$token,status:"active",issued_at:$issued,cert_not_after:$expires};
    .nodes = (if (.nodes | type) == "object" then .nodes else {} end) |
    .readers = (if (.readers | type) == "array" then .readers else [] end) |
    if (.readers | length) == 0 then .readers = [{role:"reader",identities:[current_identity]}] else . end |
    .readers[0].role = "reader" |
    .readers[0].identities =
      (if (.readers[0].identities | type) == "array" then .readers[0].identities
       elif (.readers[0].fingerprint256 | type) == "string" and (.readers[0].token | type) == "string" then
         [{fingerprint256:.readers[0].fingerprint256,token:.readers[0].token,status:"active"}]
       else [] end) |
    if any(.readers[0].identities[]; .fingerprint256 == $fp) then
      .readers[0].identities |= map(if .fingerprint256 == $fp then
        .token = $token | .status = "active" | .issued_at = $issued | .cert_not_after = $expires
      else . end)
    elif (.readers[0].identities | length) == 0 then
      .readers[0].identities = [current_identity]
    else error("configured reader identity does not match the local certificate") end |
    del(.readers[0].fingerprint256,.readers[0].token) |
    .policy = (if (.policy | type) == "object" then .policy else {} end) |
    .policy.version = (.policy.version // "1") |
    .policy.rules = (if (.policy.rules | type) == "object" then .policy.rules else {} end) |
    .policy.rules.require_signed_updates = true |
    .policy.rules.allow_remote_commands = false |
    .policy.rules.allow_cloud_push = false
  ' "$config"
}
