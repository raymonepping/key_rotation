#!/usr/bin/env bash
# scripts/verify.sh — 25-point end-to-end check of key_rotation. Read-only.
set -euo pipefail
# shellcheck source=scripts/common.sh
source "$(dirname -- "$0")/common.sh"
cd "$KROT_ROOT"

pass=0; fail=0
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad()   { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=$((fail + 1)); }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
healthy() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(podman container inspect "$1" --format '{{.State.Health.Status}}' 2>/dev/null)" = healthy ] && return 0
    sleep 3
  done
  return 1
}

api_port=$(krot_conf KROT_PORT_API)
web_port=$(krot_conf KROT_PORT_WEB)

echo "── infrastructure ──"
# 1
check " 1  Podman machine running" podman info

# 2
check " 2  krot-internal network present" podman network exists krot-internal

# 3
check " 3  vault-s container healthy" healthy krot-vault-s

# 4
vault_node vault-s
s=$(vault_json 2>/dev/null || echo '{}')
check " 4  vault-s not sealed" jq -e '.initialized and (.sealed | not)' <<<"$s"

# 5
check " 5  vault-1 container healthy" healthy krot-vault-1

# 6
vault_node vault-1
s=$(vault_json 2>/dev/null || echo '{}')
check " 6  vault-1 not sealed" jq -e '.initialized and (.sealed | not)' <<<"$s"

# 7
check " 7  vault-1 is Enterprise" bash -c 'vault_node vault-1; vault status -format=json | jq -e ".version | test(\"ent\")"'

echo "── Vault configuration ──"
vault_root vault

# 8
check " 8  KV v2 mount exists on vault-1" bash -c 'vault secrets list -format=json | jq -e "has(\"kv/\")"'

# 9
check " 9  Transit mount exists on vault-1" bash -c 'vault secrets list -format=json | jq -e "has(\"transit/\")"'

# 10
check "10  booklib-aes key exists" vault read transit/keys/booklib-aes

# 11
check "11  KV seed booklib/api present" vault kv get -mount=kv booklib/api

# 12
check "12  KV seed booklib/api-auth present" vault kv get -mount=kv booklib/api-auth

# 13
check "13  krot-booklib AppRole exists" vault read auth/approle/role/krot-booklib

unset VAULT_TOKEN

echo "── app plane identity ──"
# 14
check "14  krot-rotator container healthy" healthy krot-rotator

# 15
check "15  krot-vault-agent container healthy" healthy krot-vault-agent

# 16
check "16  token file present and non-empty" podman exec krot-vault-agent test -s /vault/secrets/token

# 17
check "17  token valid (vault token lookup)" podman exec krot-vault-agent sh -c 'VAULT_TOKEN=$(cat /vault/secrets/token) vault token lookup >/dev/null'

echo "── app layer ──"
# 18
check "18  krot-booklib container healthy" healthy krot-booklib

# 19
h=$(curl -sfk "https://127.0.0.1:$web_port/health" 2>/dev/null || curl -sf "http://127.0.0.1:$api_port/health" 2>/dev/null || echo '{}')
check "19  /health returns ok:true" jq -e '.ok' <<<"$h"

# 20
s=$(curl -sfk "https://127.0.0.1:$web_port/api/status" 2>/dev/null || curl -sf "http://127.0.0.1:$api_port/api/status" 2>/dev/null || echo '{}')
check "20  /api/status returns version > 0" jq -e '.version > 0' <<<"$s"

# 21
d=$(curl -sfk "https://127.0.0.1:$web_port/api/demo-state" 2>/dev/null || curl -sf "http://127.0.0.1:$api_port/api/demo-state" 2>/dev/null || echo '{}')
check "21  /api/demo-state returns ok:true" jq -e '.ok' <<<"$d"

# 22
tk=$(curl -sfk -X POST "https://127.0.0.1:$web_port/api/test-key" 2>/dev/null || curl -sf -X POST "http://127.0.0.1:$api_port/api/test-key" 2>/dev/null || echo '{}')
check "22  /api/test-key returns 200 (valid key)" jq -e '.ok and (.status == 200)' <<<"$tk"

# 23 — a deliberately wrong key; /protected must refuse it
wrong_key=definitely-not-valid
code=$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "X-Api-Key: $wrong_key" \
  "https://127.0.0.1:$web_port/protected" 2>/dev/null ||
  curl -s -o /dev/null -w '%{http_code}' \
  -H "X-Api-Key: $wrong_key" \
  "http://127.0.0.1:$api_port/protected" 2>/dev/null)
check "23  /protected with wrong key returns 401" [ "$code" = "401" ]

echo "── frontend ──"
# 24
idx=$(curl -sfk "https://127.0.0.1:$web_port/" 2>/dev/null | grep -ci '<!doctype html>' || true)
check "24  frontend serves index.html at :$web_port" [ "$idx" -ge 1 ]

# 25
demo2=$(curl -sfk "https://127.0.0.1:$web_port/api/demo-state" 2>/dev/null || echo '{}')
check "25  frontend proxies /api/demo-state → booklib" jq -e '.ok' <<<"$demo2"

echo
echo "verify: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
