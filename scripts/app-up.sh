#!/usr/bin/env bash
# scripts/app-up.sh — build images if missing, then start the app stack.
set -euo pipefail
# shellcheck source=scripts/common.sh
source "$(dirname -- "$0")/common.sh"

prefix=$(krot_conf KROT_IMAGE_PREFIX)
tag=$(krot_conf KROT_IMAGE_TAG)

for t in booklib frontend; do
  if ! podman image exists "$prefix/$t:$tag"; then
    echo "app-up: $prefix/$t:$tag not found — building"
    "$KROT_ROOT/scripts/app-build.sh" "$t"
  fi
done

"$KROT_ROOT/scripts/compose.sh" app up -d
echo "app-up: stack started"
echo "  UI:    https://127.0.0.1:$(krot_conf KROT_PORT_WEB)/"
echo "  API:   http://127.0.0.1:$(krot_conf KROT_PORT_API)/health"
echo "  Vault: https://localhost:$(krot_conf KROT_PORT_VAULT_1)/ui"
