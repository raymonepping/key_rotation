#!/usr/bin/env bash
# scripts/bootstrap.sh — first run, from zero to verified. Idempotent.
set -euo pipefail
# shellcheck source=scripts/common.sh
source "$(dirname -- "$0")/common.sh"
cd "$KROT_ROOT"

log() { printf '\033[1m[bootstrap]\033[0m %s\n' "$*"; }
run() { log "$*"; "$KROT_ROOT/scripts/$1.sh" "${@:2}"; }

log "Step 1/9: Podman pre-flight"
run podman-check

log "Step 2/9: Network"
run network

log "Step 3/9: TLS — lab CA + listener certificate"
run gen-certs

log "Step 4/9: Vault — initialise vault-s (Shamir) and vault-1 (Transit auto-unseal)"
run vault-bootstrap

log "Step 5/9: Terraform — vault-seal (AppRoles on vault-s)"
"$KROT_ROOT/scripts/tf.sh" vault-seal apply

log "Step 6/9: Rotator credentials — seal plane"
"$KROT_ROOT/scripts/rotator-bootstrap.sh" seal

log "Step 7/9: Seal plane — rotator + agent"
run seal-up
run vault-recreate

log "Step 8/9: Terraform — vault-platform (KV, Transit, AppRoles on vault-1)"
"$KROT_ROOT/scripts/tf.sh" vault-platform apply

log "Step 9/9: Rotator credentials — app plane + build + start"
"$KROT_ROOT/scripts/rotator-bootstrap.sh" app
run app-build
run app-up

log "Verifying..."
run verify

log "Done. key_rotation is up."
