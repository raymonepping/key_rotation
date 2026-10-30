#!/usr/bin/env bash
# scripts/vault-down.sh — stop vault-1 then the seal stack (data kept).
set -euo pipefail
# shellcheck source=scripts/common.sh
source "$(dirname -- "$0")/common.sh"

"$KROT_ROOT/scripts/compose.sh" vault stop 2>/dev/null || true
"$KROT_ROOT/scripts/compose.sh" seal stop 2>/dev/null || true
echo "vault-down: vault stacks stopped"
