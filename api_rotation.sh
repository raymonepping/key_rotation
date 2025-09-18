#!/usr/bin/env bash
set -euo pipefail

# Config
MOUNT="${MOUNT:-kv}"
PATH_IN_KV="${PATH_IN_KV:-booklib/api-auth}"
TRANSIT_KEY="${TRANSIT_KEY:-booklib-aes}"
URL="${URL:-http://localhost:3001/protected}"
SOURCE="${SOURCE:-vault}"  # use 'vault' since your server loads from Vault

mask(){ local s="$1"; [ "${#s}" -gt 6 ] && echo "${s:0:4}***" || echo "${s:0:1}***"; }

get_from_vault() {
  local cur ct
  cur="$(vault kv get -field=password "$MOUNT/$PATH_IN_KV" 2>/dev/null || true)"
  if [ -n "$cur" ]; then echo "$cur"; return; fi
  ct="$(vault kv get -format=json "$MOUNT/$PATH_IN_KV" | jq -r '.data.data.ciphertext')"
  vault write -format=json "transit/decrypt/$TRANSIT_KEY" ciphertext="$ct" \
    | jq -r '.data.plaintext' | base64 -d
}

curl_key() {
  local key="$1"
  echo "-> curl with key $(mask "$key")"
  curl -s -i -H "X-Api-Key: $key" "$URL" | sed -n '1,5p'
  echo
}

wait_until_accepts() {
  local key="$1" tries="${2:-10}" delay="${3:-0.5}"
  for _ in $(seq 1 "$tries"); do
    if curl -s -o /dev/null -w "%{http_code}" -H "X-Api-Key: $key" "$URL" | grep -q '^200$'; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

case "${1:-}" in
  test)
    echo "=== Test current key ==="
    CUR="$(get_from_vault)"
    curl_key "$CUR"
    ;;

  rotate-test)
    echo "=== Rotate + test previous & current ==="
    PREV="$(get_from_vault)"
    echo "Previous: $(mask "$PREV")"

    ./secret_rotation.sh rotate --mount "$MOUNT" --path "$PATH_IN_KV" --field password --show --mask=false >/dev/null

    CUR="$(get_from_vault)"
    echo "Current:  $(mask "$CUR")"
    echo

    echo "-- Expect 200 with PREV (grace window) --"
    curl_key "$PREV"

    echo "-- Wait for server to load CUR, then expect 200 --"
    if wait_until_accepts "$CUR" 12 0.5; then
      curl_key "$CUR"
    else
      echo "!! Server hasn't loaded CUR yet. Consider lowering APIKEY_REFRESH_MS or increasing wait." >&2
      curl_key "$CUR"
      exit 1
    fi
    ;;

  *)
    echo "Usage: $0 test | rotate-test"
    exit 1
    ;;
esac
