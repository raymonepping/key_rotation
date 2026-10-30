#!/usr/bin/env bash
# scripts/test-rotation.sh — prove both machine identities self-heal
# credential failures without human intervention.
set -uo pipefail
# shellcheck source=scripts/common.sh
source "$(dirname -- "$0")/common.sh"
set +e
cd "$KROT_ROOT"
pass=0 fail=0
ok()  { printf '  \033[32mok\033[0m    %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }
wait_for() {
  local max=$1 d=$2 t=0
  shift 2
  until "$@" >/dev/null 2>&1; do
    t=$((t + 5)); [ "$t" -ge "$max" ] && { bad "$d (not within ${max}s)"; return 1; }
    sleep 5
  done
  ok "$d (${t}s)"
}

ROLE=krot-booklib
META=/run/approle/$ROLE/metadata.json
web="https://127.0.0.1:$(krot_conf KROT_PORT_WEB)"
agent_token_ok() { podman exec krot-vault-agent sh -c 'VAULT_TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null) vault token lookup >/dev/null 2>&1'; }
agent_accessor()  { podman exec krot-vault-agent sh -c 'VAULT_TOKEN=$(cat "$TOKEN_FILE") vault token lookup -format=json' | jq -r .data.accessor; }
secret_accessor() { podman exec krot-rotator cat "$META" | jq -r .secret_id_accessor; }
restarts()        { podman inspect krot-vault-agent --format '{{.RestartCount}}'; }
api_works()       { curl -sfk "$web/health" | jq -e '.ok' >/dev/null 2>&1; }
accessor_dead()   { ! vault write auth/approle/role/$ROLE/secret-id-accessor/lookup secret_id_accessor="$1" >/dev/null 2>&1; }

vault_node vault-1
vault_root vault
api_works && ok "baseline: the API responds to /health" || bad "baseline: the API responds to /health"

echo
echo "1. The agent's token is revoked"
acc=$(agent_accessor)
r0=$(restarts)
vault token revoke -accessor "$acc" >/dev/null
api_works && bad "the API fails while its token is dead" || ok "the API fails while its token is dead"
wait_for 180 "watchdog restarts the agent and it logs in again" agent_token_ok
[ "$(agent_accessor)" != "$acc" ] && ok "the agent holds a new token" || bad "the agent holds a new token"
[ "$(restarts)" -gt "$r0" ] && ok "restart: on-failure did the work" || bad "agent restart count increased"
wait_for 30 "the API is healthy again" api_works

echo
echo "2. make rotate-now"
old=$(secret_accessor)
make --no-print-directory rotate-now >/dev/null
new_secret() { [ "$(secret_accessor)" != "$old" ]; }
wait_for 30 "the rotator issues a new secret-id" new_secret
accessor_dead "$old" && ok "the replaced secret-id is destroyed in Vault" || bad "the replaced secret-id is destroyed in Vault"
agent_token_ok && ok "the agent's token is unaffected" || bad "the agent's token is unaffected"
api_works && ok "the API keeps working" || bad "the API keeps working"

echo
echo "3. Worst case: the secret-id is destroyed AND the token revoked"
old=$(secret_accessor)
vault write auth/approle/role/$ROLE/secret-id-accessor/destroy secret_id_accessor="$old" >/dev/null
vault token revoke -accessor "$(agent_accessor)" >/dev/null
wait_for 180 "the rotator notices Vault no longer knows the secret-id and issues a new one" new_secret
wait_for 240 "the agent logs in with the new secret-id, no human involved" agent_token_ok
wait_for 30 "the API is healthy again" api_works

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
