#!/usr/bin/env bash
set -euo pipefail

# Vault KV v2 helper: read, rotate, prune, history, rollback, transit encrypt/decrypt
# Requirements: vault, jq, openssl

# Defaults
MOUNT="${KV_MOUNT:-kv}"
PATH_IN_KV="${KV_PATH:-booklib/api}"
FIELD="${KV_FIELD:-password}"
LENGTH="${KV_LENGTH:-24}"
CAS_SAFE="${KV_CAS_SAFE:-true}"      # true|false
QUIET="${KV_QUIET:-false}"           # true|false
JSON_OUT="${KV_JSON:-false}"         # true|false
VAULT_NAMESPACE="${VAULT_NAMESPACE:-${VAULT_NAMESPACE:-}}"

# Transit
TRANSIT_KEY="${TRANSIT_KEY:-}"       # e.g., booklib-aes
CIPHER_FIELD="${CIPHER_FIELD:-ciphertext}"
DECRYPT_ON_READ="${DECRYPT_ON_READ:-false}"

# Show options
SHOW_PLAINTEXT="${SHOW_PLAINTEXT:-false}"  # true|false
MASK_OUTPUT="${MASK_OUTPUT:-true}"         # true|false

# Ops
PRUNE_ON_ROTATE="false"
DESTROY_MODE="false"
DRY_RUN="false"
YES="false"

# Other
KEEP="1"
LIMIT="0"
SINCE=""
TARGET_VERSION=""
SUPPLIED_VALUE=""

usage() {
  cat <<EOF
Usage:
  $0 read     [--mount M] [--path P] [--field F] [--json] [--quiet] [--decrypt] [--transit-key K] [--cipher-field C]
  $0 rotate   [--mount M] [--path P] [--field F] [--value V] [--len N] [--no-cas]
              [--prune] [--destroy] [--json] [--quiet] [--dry-run] [--yes]
              [--transit-key K] [--cipher-field C] [--show] [--mask|--mask=false]
  $0 prune    [--mount M] [--path P] [--keep N] [--destroy] [--dry-run] [--yes]
  $0 history  [--mount M] [--path P] [--limit N] [--since ISO8601] [--json]
  $0 rollback [--mount M] [--path P] [--field F] --to N [--no-cas] [--quiet]
              [--transit-key K] [--cipher-field C]

Options:
  --mount M       KV v2 mount, default: ${MOUNT}
  --path P        Secret path, default: ${PATH_IN_KV}
  --field F       Field to read or rotate, default: ${FIELD}
  --value V       Explicit value for rotate
  --len N         Bytes for openssl rand -base64, default: ${LENGTH}
  --no-cas        Disable CAS safety on rotate or rollback
  --prune         After rotate, remove previous version
  --destroy       Use destroy instead of delete when pruning
  --keep N        For prune, keep latest N versions, default: 1
  --limit N       For history, show latest N versions only
  --since ISO     For history, filter created_time >= ISO8601
  --to N          For rollback, target version number
  --json          JSON output for read and history
  --quiet         Value only for read, minimal logs elsewhere
  --dry-run       Print actions, do not change Vault
  --yes           Skip confirmations for destructive actions
  --decrypt       On read, decrypt Transit ciphertext to plaintext
  --transit-key K Encrypt on rotate using Transit key K, or decrypt on read with --decrypt
  --cipher-field C Field in KV to store Transit ciphertext, default: ${CIPHER_FIELD}
  --show          After rotate with Transit, print plaintext once
  --mask[=true]   Mask plaintext on --show (default true). Use --mask=false for full plaintext.
EOF
}

log() { [ "$QUIET" = "true" ] && return 0 || printf '%s\n' "$*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }; }

confirm() {
  local prompt="$1"
  if [ "$YES" = "true" ]; then
    return 0
  fi
  printf "%s [y/N]: " "$prompt" >&2
  read -r ans || true
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) echo "Aborted." >&2; exit 1 ;;
  esac
}

mask_value() {
  # Keep first 3 and last 3 chars, mask middle. If short, mask all but first.
  local s="$1" n=${#1}
  if [ "$n" -le 6 ]; then
    printf '%s\n' "${s:0:1}***"
  else
    printf '%s\n' "${s:0:3}***${s: -3}"
  fi
}

vlt() {
  if [ -n "${VAULT_NAMESPACE:-}" ]; then
    VAULT_NAMESPACE="$VAULT_NAMESPACE" vault "$@"
  else
    vault "$@"
  fi
}

parse_args() {
  ACTION="${1:-}"
  [ -z "${ACTION}" ] && usage && exit 1
  shift || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mount) MOUNT="$2"; shift 2;;
      --path) PATH_IN_KV="$2"; shift 2;;
      --field) FIELD="$2"; shift 2;;
      --value) SUPPLIED_VALUE="$2"; shift 2;;
      --len) LENGTH="$2"; shift 2;;
      --no-cas) CAS_SAFE="false"; shift 1;;
      --prune) PRUNE_ON_ROTATE="true"; shift 1;;
      --destroy) DESTROY_MODE="true"; shift 1;;
      --keep) KEEP="$2"; shift 2;;
      --limit) LIMIT="$2"; shift 2;;
      --since) SINCE="$2"; shift 2;;
      --to) TARGET_VERSION="$2"; shift 2;;
      --json) JSON_OUT="true"; shift 1;;
      --quiet) QUIET="true"; shift 1;;
      --dry-run) DRY_RUN="true"; shift 1;;
      --yes) YES="true"; shift 1;;
      --decrypt) DECRYPT_ON_READ="true"; shift 1;;
      --transit-key) TRANSIT_KEY="$2"; shift 2;;
      --cipher-field) CIPHER_FIELD="$2"; shift 2;;
      --show) SHOW_PLAINTEXT="true"; shift 1;;
      --mask) MASK_OUTPUT="true"; shift 1;;
      --mask=false) MASK_OUTPUT="false"; shift 1;;
      -h|--help) usage; exit 0;;
      *) echo "Unknown arg: $1" >&2; usage; exit 1;;
    esac
  done
}

get_current_version() {
  vlt kv get -format=json "${MOUNT}/${PATH_IN_KV}" | jq -r '.data.metadata.version'
}

transit_encrypt() {
  local plaintext="$1" b64 ct
  b64="$(printf '%s' "$plaintext" | base64)"
  ct="$(vlt write -format=json "transit/encrypt/${TRANSIT_KEY}" plaintext="$b64" \
        | jq -r '.data.ciphertext')"
  printf '%s' "$ct"
}

transit_decrypt() {
  local ciphertext="$1" b64 pt
  b64="$(vlt write -format=json "transit/decrypt/${TRANSIT_KEY}" ciphertext="$ciphertext" \
        | jq -r '.data.plaintext')"
  pt="$(printf '%s' "$b64" | base64 -d)"
  printf '%s' "$pt"
}

read_value() {
  if [ "$DECRYPT_ON_READ" = "true" ]; then
    local ct
    ct="$(vlt kv get -format=json "${MOUNT}/${PATH_IN_KV}" | jq -r --arg f "$CIPHER_FIELD" '.data.data[$f]')"
    if [ "$ct" = "null" ] || [ -z "$ct" ]; then
      echo "No ciphertext in field '$CIPHER_FIELD' at ${MOUNT}/${PATH_IN_KV}" >&2
      exit 1
    fi
    transit_decrypt "$ct"
    return
  fi

  if [ "$JSON_OUT" = "true" ]; then
    vlt kv get -format=json "${MOUNT}/${PATH_IN_KV}"
    return
  fi

  if [ "$QUIET" = "true" ]; then
    vlt kv get -field="${FIELD}" "${MOUNT}/${PATH_IN_KV}"
  else
    vlt kv get "${MOUNT}/${PATH_IN_KV}"
  fi
}

rotate_with_cas_retry() {
  local value ver tries=5 out_field out_value
  value="${SUPPLIED_VALUE:-$(openssl rand -base64 "${LENGTH}")}"

  if [ -n "$TRANSIT_KEY" ]; then
    out_field="$CIPHER_FIELD"
    out_value="$(transit_encrypt "$value")"
  else
    out_field="$FIELD"
    out_value="$value"
  fi

  for i in $(seq 1 $tries); do
    ver="$(get_current_version)"
    log "CAS attempt $i/$tries, current version=${ver}"
    if [ "$DRY_RUN" = "true" ]; then
      log "[dry-run] would: kv put -cas=${ver} ${MOUNT}/${PATH_IN_KV} ${out_field}=[REDACTED]"
      printf '%s\n' "$value"
      return 0
    fi
    if vlt kv put -cas="$ver" "${MOUNT}/${PATH_IN_KV}" "${out_field}=${out_value}" >/dev/null; then
      printf '%s\n' "$value"
      return 0
    fi
    sleep 0.5
  done
  echo "CAS failed after $tries attempts" >&2
  exit 1
}

rotate_no_cas() {
  local value out_field out_value
  value="${SUPPLIED_VALUE:-$(openssl rand -base64 "${LENGTH}")}"

  if [ -n "$TRANSIT_KEY" ]; then
    out_field="$CIPHER_FIELD"
    out_value="$(transit_encrypt "$value")"
  else
    out_field="$FIELD"
    out_value="$value"
  fi

  if [ "$DRY_RUN" = "true" ]; then
    log "[dry-run] would: kv put ${MOUNT}/${PATH_IN_KV} ${out_field}=[REDACTED]"
    printf '%s\n' "$value"
    return 0
  fi
  vlt kv put "${MOUNT}/${PATH_IN_KV}" "${out_field}=${out_value}" >/dev/null
  printf '%s\n' "$value"
}

rotate_value() {
  local before_ver after_ver new_value
  before_ver="$(get_current_version || echo 0)"
  log "Rotating ${MOUNT}/${PATH_IN_KV}, field=${FIELD}, before version=${before_ver} (CAS=${CAS_SAFE})"

  if [ "$CAS_SAFE" = "true" ]; then
    new_value="$(rotate_with_cas_retry)"
  else
    new_value="$(rotate_no_cas)"
  fi

  after_ver="$(get_current_version || echo 0)"
  log "Rotate complete, new version=${after_ver}"

  if [ "$PRUNE_ON_ROTATE" = "true" ] && [ "$before_ver" != "0" ] && [ "$after_ver" != "$before_ver" ]; then
    if [ "$DESTROY_MODE" = "true" ]; then
      if [ "$DRY_RUN" = "true" ]; then
        log "[dry-run] would: kv destroy -versions=${before_ver} ${MOUNT}/${PATH_IN_KV}"
      else
        confirm "About to DESTROY version ${before_ver} of ${MOUNT}/${PATH_IN_KV}. This is irreversible. Continue"
        vlt kv destroy -versions="$before_ver" "${MOUNT}/${PATH_IN_KV}"
        log "Destroyed previous version=${before_ver}"
      fi
    else
      if [ "$DRY_RUN" = "true" ]; then
        log "[dry-run] would: kv delete -versions=${before_ver} ${MOUNT}/${PATH_IN_KV}"
      else
        vlt kv delete -versions="$before_ver" "${MOUNT}/${PATH_IN_KV}"
        log "Deleted previous version=${before_ver}"
      fi
    fi
  fi

  # Output block
  if [ -n "$TRANSIT_KEY" ] && [ "$SHOW_PLAINTEXT" = "true" ]; then
    if [ "$MASK_OUTPUT" = "true" ]; then
      mask_value "$new_value"
    else
      printf '%s\n' "$new_value"
    fi
  elif [ "$JSON_OUT" = "true" ]; then
    vlt kv get -format=json "${MOUNT}/${PATH_IN_KV}"
  elif [ "$QUIET" = "true" ]; then
    printf '%s\n' "$new_value"
  else
    vlt kv get "${MOUNT}/${PATH_IN_KV}"
  fi
}

prune_keep_latest_n() {
  log "Prune ${MOUNT}/${PATH_IN_KV}, keep latest ${KEEP}, mode=$([ "$DESTROY_MODE" = "true" ] && echo destroy || echo delete)"
  local versions total count
  local to_remove=()
  versions="$(vlt kv metadata get -format=json "${MOUNT}/${PATH_IN_KV}" | jq -r '.data.versions | keys[]' | sort -n)"
  [ -z "$versions" ] && { log "No versions found."; return 0; }

  total=$(echo "$versions" | wc -l | tr -d ' ')
  [ "$total" -le "$KEEP" ] && { log "Nothing to prune. total=${total} <= keep=${KEEP}"; return 0; }

  count=0
  while read -r v; do
    count=$((count+1))
    if [ $count -le $((total-KEEP)) ]; then
      to_remove+=("$v")
    fi
  done <<<"$versions"

  [ "${#to_remove[@]}" -eq 0 ] && { log "Nothing to prune."; return 0; }

  local csv
  csv="$(IFS=,; echo "${to_remove[*]}")"
  if [ "$DRY_RUN" = "true" ]; then
    log "[dry-run] would: kv $([ "$DESTROY_MODE" = "true" ] && echo destroy || echo delete) -versions=${csv} ${MOUNT}/${PATH_IN_KV}"
    return 0
  fi

  if [ "$DESTROY_MODE" = "true" ]; then
    confirm "About to DESTROY versions ${csv} of ${MOUNT}/${PATH_IN_KV}. This is irreversible. Continue"
    vlt kv destroy -versions="${csv}" "${MOUNT}/${PATH_IN_KV}"
  else
    vlt kv delete -versions="${csv}" "${MOUNT}/${PATH_IN_KV}"
  fi
  log "Pruned versions: ${csv}"
}

history_show() {
  local meta items
  meta="$(vlt kv metadata get -format=json "${MOUNT}/${PATH_IN_KV}")"

  if [ "$JSON_OUT" = "true" ]; then
    echo "$meta"
    return
  fi

  local jq_filter='
    .data.versions
    | to_entries
    | sort_by(.key|tonumber)
    | reverse
    | map({
        version: (.key|tonumber),
        created: (.value.created_time // ""),
        deletion: (.value.deletion_time // ""),
        destroyed: (.value.destroyed // false),
        status: (if (.value.destroyed // false) then "destroyed"
                 elif ((.value.deletion_time // "") | length) > 0 then "deleted"
                 else "active" end)
      })
  '
  items="$(echo "$meta" | jq -c "$jq_filter")"

  if [ -n "$SINCE" ]; then
    items="$(echo "$items" | jq --arg since "$SINCE" '[.[] | select(.created >= $since)]')"
  fi
  if [ "$LIMIT" != "0" ]; then
    items="$(echo "$items" | jq ".[0:$LIMIT]")"
  fi

  printf "History for %s/%s\n" "$MOUNT" "$PATH_IN_KV"
  printf "%-8s %-24s %-24s %-10s\n" "Version" "Created" "Deletion" "Status"
  echo "$items" \
    | jq -r '.[] | [.version, .created, .deletion, .status] | @tsv' \
    | while IFS=$'\t' read -r v c d s; do
        printf "%-8s %-24s %-24s %-10s\n" "$v" "$c" "$d" "$s"
      done
}

rollback_to_version() {
  [ -z "$TARGET_VERSION" ] && { echo "Missing --to <version>" >&2; exit 1; }

  local cur_ver meta has_cipher has_field out_field out_value new_val
  cur_ver="$(get_current_version || echo 0)"
  log "Rollback ${MOUNT}/${PATH_IN_KV} to version=${TARGET_VERSION} (current=${cur_ver})"

  # Read target version once
  meta="$(vlt kv get -version="$TARGET_VERSION" -format=json "${MOUNT}/${PATH_IN_KV}")"
  has_cipher="$(echo "$meta" | jq -r --arg f "$CIPHER_FIELD" '(.data.data[$f] != null)')"
  has_field="$(echo "$meta" | jq -r --arg f "$FIELD" '(.data.data[$f] != null)')"

  if [ "$has_cipher" = "true" ]; then
    # Prefer ciphertext if present
    out_field="$CIPHER_FIELD"
    out_value="$(echo "$meta" | jq -r --arg f "$CIPHER_FIELD" '.data.data[$f]')"
    [ "$out_value" = "null" ] && { echo "No ciphertext in ${CIPHER_FIELD} at v${TARGET_VERSION}" >&2; exit 1; }
  elif [ "$has_field" = "true" ]; then
    out_field="$FIELD"
    out_value="$(echo "$meta" | jq -r --arg f "$FIELD" '.data.data[$f]')"
    [ "$out_value" = "null" ] && { echo "No value in ${FIELD} at v${TARGET_VERSION}" >&2; exit 1; }
    new_val="$out_value"  # used only for --quiet plaintext echo
  else
    echo "Neither '${CIPHER_FIELD}' nor '${FIELD}' present at v${TARGET_VERSION}" >&2
    exit 1
  fi

  if [ "$DRY_RUN" = "true" ]; then
    log "[dry-run] would: kv put $([ "$CAS_SAFE" = "true" ] && echo -n "-cas=${cur_ver} ")${MOUNT}/${PATH_IN_KV} ${out_field}=[FROM v${TARGET_VERSION}]"
    # If plaintext path, optionally print value when --quiet
    [ "$out_field" = "$FIELD" ] && [ "$QUIET" = "true" ] && printf '%s\n' "$new_val" || true
    return 0
  fi

  if [ "$CAS_SAFE" = "true" ]; then
    vlt kv put -cas="$cur_ver" "${MOUNT}/${PATH_IN_KV}" "${out_field}=${out_value}" >/dev/null
  else
    vlt kv put "${MOUNT}/${PATH_IN_KV}" "${out_field}=${out_value}" >/dev/null
  fi

  log "Rollback complete. New head version: $(get_current_version)"

  # Output: if we rolled back plaintext and --quiet, print it; otherwise show the secret
  if [ "$out_field" = "$FIELD" ] && [ "$QUIET" = "true" ]; then
    printf '%s\n' "$new_val"
  else
    vlt kv get "${MOUNT}/${PATH_IN_KV}"
  fi
}

main() {
  need vault
  need jq
  need openssl

  parse_args "$@"

  case "$ACTION" in
    read)     read_value ;;
    rotate)   rotate_value ;;
    prune)    prune_keep_latest_n ;;
    history)  history_show ;;
    rollback) rollback_to_version ;;
    *) usage; exit 1;;
  esac
}

main "$@"
# End of secret_rotation.sh