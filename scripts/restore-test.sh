#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
artifact="${OPENBAO_RESTORE_ARTIFACT:?set encrypted snapshot path}"
checksum="${OPENBAO_RESTORE_CHECKSUM:?set snapshot checksum path}"
identity="${OPENBAO_AGE_IDENTITY_FILE:?set age identity path}"
production_cluster_id="${OPENBAO_PRODUCTION_CLUSTER_ID:?set production cluster ID for exclusion}"
evidence="${OPENBAO_RESTORE_EVIDENCE:?set evidence JSON output path}"
restored_probe_token_file="${OPENBAO_RESTORED_PROBE_TOKEN_FILE:?set token file for a read-only identity stored in the restored snapshot}"

[[ "$environment" != production ]]
[[ "${OPENBAO_ISOLATED_RESTORE_ACKNOWLEDGED:-false}" == true ]]
[[ -f "$artifact" && -f "$checksum" && -f "$identity" ]]
[[ -f "$restored_probe_token_file" && ! -L "$restored_probe_token_file" ]]
case "$(stat -c '%a' "$restored_probe_token_file")" in
  400|600) ;;
  *) echo 'OPENBAO_RESTORE=FAIL restored probe token file permissions must be 0400 or 0600' >&2; exit 1 ;;
esac
for command in age bao jq sha256sum shred stat; do command -v "$command" >/dev/null; done
(cd "$(dirname "$artifact")" && sha256sum -c "$(basename "$checksum")") >/dev/null

set +e
before="$(bao status -format=json 2>/dev/null)"
before_status=$?
set -e
[[ "$before_status" == 0 || "$before_status" == 2 ]]
target_cluster_id="$(jq -r '.cluster_id // ""' <<<"$before")"
[[ -n "$target_cluster_id" && "$target_cluster_id" != "$production_cluster_id" ]]
[[ "$BAO_ADDR" == *127.0.0.1* || "$BAO_ADDR" == *localhost* || "$BAO_ADDR" == *restore* ]]

umask 077
plain="$(mktemp)"
cleanup() {
  unset BAO_TOKEN restored_probe_token 2>/dev/null || true
  if [[ -f "$plain" ]]; then shred --remove --zero "$plain" 2>/dev/null || true; fi
}
trap cleanup EXIT
age --decrypt --identity "$identity" --output "$plain" "$artifact"
bao operator raft snapshot inspect "$plain" >/dev/null
bao operator raft snapshot restore -force "$plain" >/dev/null
unset BAO_TOKEN
cleanup
trap cleanup EXIT

python3 "$(dirname "$0")/unseal_from_files.py"
after="$(bao status -format=json)"
[[ "$(jq -r '.initialized' <<<"$after")" == true ]]
[[ "$(jq -r '.sealed' <<<"$after")" == false ]]
restored_cluster_id="$(jq -r '.cluster_id' <<<"$after")"
[[ -n "$restored_cluster_id" ]]

restored_probe_token="$(< "$restored_probe_token_file")"
[[ -n "$restored_probe_token" ]]
export BAO_TOKEN="$restored_probe_token"
python3 "$(dirname "$0")/verify_secret_hash.py" \
  --path "${OPENBAO_RESTORE_PROBE_PATH:?set representative non-production probe path}" \
  --field "${OPENBAO_RESTORE_PROBE_FIELD:?set representative probe field}" \
  --expected-sha256 "${OPENBAO_RESTORE_PROBE_SHA256:?set expected probe hash}"
unset BAO_TOKEN restored_probe_token

started_epoch="${OPENBAO_RESTORE_STARTED_EPOCH:?record restore test start epoch}"
completed_epoch="$(date +%s)"
duration="$((completed_epoch - started_epoch))"
jq -n \
  --arg environment "$environment" \
  --arg sourceArtifact "$(basename "$artifact")" \
  --arg sourceSha256 "$(awk '{print $1}' "$checksum")" \
  --arg restoredClusterIdHash "$(printf '%s' "$restored_cluster_id" | sha256sum | awk '{print $1}')" \
  --argjson durationSeconds "$duration" \
  '{schemaVersion:1,environment:$environment,isolated:true,sourceArtifact:$sourceArtifact,sourceSha256:$sourceSha256,restoredClusterIdHash:$restoredClusterIdHash,durationSeconds:$durationSeconds,initialized:true,sealed:false,representativeSecretHashVerified:true,restore:"PASS"}' \
  > "$evidence"
chmod 400 "$evidence"
echo 'OPENBAO_RESTORE=PASS'
echo "RESTORE_DURATION_SECONDS=${duration}"
