#!/usr/bin/env bash
set -Eeuo pipefail

search_root="${1:-.}"
pattern="(BEGIN ([A-Z0-9][A-Z0-9 -]{0,63} )?PRIVATE KEY( BLOCK)?|[\"']?Authorization[\"']?[[:space:]]*:[[:space:]]*[\"']?[[:space:]]*Bearer[[:space:]]+[-A-Za-z0-9._~+/]{16,}=*|[\"']?client_secret[\"']?[[:space:]]*[:=][[:space:]]*[^[:space:]<]+|(hvs|hvr|hvb|hvp|hvS)\.[A-Za-z0-9_.:-]{8,}|s\.[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|SK[0-9a-fA-F]{32}|xox(a|b|p|r|s)-[A-Za-z0-9-]{12,}|xapp-[A-Za-z0-9-]{12,})"
path_list="$(mktemp)"
trap 'rm -f -- "$path_list"' EXIT

set +e
find "$search_root" \
  -path "$search_root/.git" -prune -o \
  \( -type f -o -type l \) -print0 > "$path_list"
find_status=$?
set -e
if (( find_status != 0 )); then
  echo "Secret scan traversal failed (find status ${find_status})." >&2
  exit "$find_status"
fi

while IFS= read -r -d '' path; do
  if [[ -L "$path" ]]; then
    echo "Secret scan refuses symbolic link: ${path}" >&2
    exit 2
  fi
  set +e
  LC_ALL=C grep -aEiq "$pattern" -- "$path"
  secret_scan_status=$?
  set -e
  case "$secret_scan_status" in
    0)
      echo 'Repository secret pattern detected.' >&2
      exit 1
      ;;
    1)
      ;;
    *)
      echo "Secret scan failed before completing (grep status ${secret_scan_status})." >&2
      exit "$secret_scan_status"
      ;;
  esac
done < "$path_list"
