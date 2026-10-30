#!/usr/bin/env bash
# scripts/common.sh — shared, host-side helpers. Source, do not execute.
#
# Host tooling talks to the two Vault nodes on their published loopback ports
# and verifies TLS against the lab CA; nothing here uses -tls-skip-verify.
set -euo pipefail
umask 077
KROT_ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KROT_STATE="$KROT_ROOT/.secrets/vault"
export VAULT_CACERT="$KROT_ROOT/vault-tls/ca-chain.pem"
unset VAULT_SKIP_VERIFY VAULT_NAMESPACE VAULT_TOKEN VAULT_TLS_SERVER_NAME

# Effective config value: .env overrides config/defaults.env.
krot_conf() {
  local name=$1 v=""
  [ -f "$KROT_ROOT/.env" ] && v=$(grep -E "^${name}=" "$KROT_ROOT/.env" | tail -1 | cut -d= -f2- || true)
  [ -n "$v" ] || v=$(grep -E "^${name}=" "$KROT_ROOT/config/defaults.env" | tail -1 | cut -d= -f2- || true)
  printf '%s' "$v"
}

# Cluster a node belongs to.
vault_cluster_of() {
  case "$1" in
  vault-s) echo seal ;;
  vault-1) echo vault ;;
  *) echo "Unknown Vault node: $1" >&2; return 1 ;;
  esac
}

vault_container() { printf 'krot-%s' "$1"; }

# Point VAULT_ADDR at one node's published port.
vault_node() {
  local port
  case "$1" in
  vault-s) port=$(krot_conf KROT_PORT_VAULT_S) ;;
  vault-1) port=$(krot_conf KROT_PORT_VAULT_1) ;;
  *) echo "Unknown Vault node: $1" >&2; return 1 ;;
  esac
  VAULT_ADDR="https://127.0.0.1:$port"
  export VAULT_ADDR
}

# `vault status` exits 2 when sealed; that is still a valid answer.
vault_json() {
  local code=0
  vault status -format=json || code=$?
  [ "$code" -eq 0 ] || [ "$code" -eq 2 ]
}

# vault_wait reachable|unsealed|active [attempts]
vault_wait() {
  local mode=$1 max=${2:-60} attempt state
  for ((attempt = 0; attempt < max; attempt++)); do
    if state=$(vault_json 2>/dev/null); then
      case "$mode" in
      reachable) return 0 ;;
      unsealed) jq -e '.initialized and (.sealed | not)' <<<"$state" >/dev/null && return 0 ;;
      active) jq -e '.initialized and (.sealed | not)' <<<"$state" >/dev/null &&
        curl -sf --cacert "$VAULT_CACERT" "$VAULT_ADDR/v1/sys/leader" | jq -e '.is_self' >/dev/null && return 0 ;;
      esac
    fi
    sleep 2
  done
  echo "Timed out waiting for $VAULT_ADDR ($mode)." >&2
  return 1
}

# Read one field from .secrets/vault/<cluster>-init.json.
vault_init_field() {
  jq -er "$2" "$KROT_STATE/$1-init.json"
}

# Lab shortcut: use the root token from the init file.
vault_root() {
  VAULT_TOKEN=$(vault_init_field "$1" '.root_token')
  export VAULT_TOKEN
}

krot_container_state() {
  podman container inspect "$1" --format '{{.State.Status}}' 2>/dev/null || echo "not created"
}

# The seal agent's sink is a volume of the seal stack that compose/vault
# mounts as external.
ensure_seal_token_volume() {
  podman volume exists krot-seal_seal-token ||
    podman volume create --label com.docker.compose.project=krot-seal \
      --label com.docker.compose.volume=seal-token krot-seal_seal-token >/dev/null
}
