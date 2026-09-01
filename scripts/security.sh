#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
scan_dir="$(mktemp -d)"

cleanup() {
  find "$scan_dir" -type f -delete
  find "$scan_dir" -depth -type d -empty -delete
}
trap cleanup EXIT

scripts/reject_repository_secrets.sh .

gitleaks dir . --no-banner --redact --config .gitleaks.toml \
  --report-format json --report-path "$scan_dir/working-tree.json"
gitleaks git . --no-banner --redact --config .gitleaks.toml \
  --report-format json --report-path "$scan_dir/history.json" --log-opts='--all'
[[ "$(jq 'length' "$scan_dir/working-tree.json")" == 0 ]]
[[ "$(jq 'length' "$scan_dir/history.json")" == 0 ]]

python3 scripts/verify_vulnerability_gate.py
python3 scripts/verify_plugin_supply_chain.py
(cd artifacts/supply-chain && sha256sum -c SHA256SUMS)

echo 'OPENBAO_SECRET_SCAN=PASS'
echo 'OPENBAO_FULL_HISTORY_SECRET_SCAN=PASS'
echo 'OPENBAO_SECURITY_VALIDATION=PASS'
