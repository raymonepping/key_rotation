#!/usr/bin/env bash
# scripts/app-build.sh [booklib|frontend …] — build the app images.
set -euo pipefail
# shellcheck source=scripts/common.sh
source "$(dirname -- "$0")/common.sh"
export COPYFILE_DISABLE=1

targets=${*:-booklib frontend}
prefix=$(krot_conf KROT_IMAGE_PREFIX)
tag=$(krot_conf KROT_IMAGE_TAG)

for t in $targets; do
  case "$t" in
  booklib)  ctx="$KROT_ROOT/booklib" ;;
  frontend) ctx="$KROT_ROOT/frontend" ;;
  *) echo "app-build: unknown target '$t'" >&2; exit 64 ;;
  esac
  xattr -rc "$ctx" 2>/dev/null || true
  find "$ctx" -name '._*' -not -path '*/node_modules/*' -delete 2>/dev/null || true
  echo "app-build: building $prefix/$t:$tag"
  podman build -q --format docker \
    --build-arg NODE_IMAGE="$(krot_conf NODE_IMAGE)" \
    --build-arg NGINX_IMAGE="$(krot_conf NGINX_IMAGE)" \
    -t "$prefix/$t:$tag" -f "$ctx/Containerfile" "$ctx" >/dev/null
done
