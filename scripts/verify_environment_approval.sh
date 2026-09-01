#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
repository="${GITHUB_REPOSITORY:?must run in GitHub Actions}"
run_id="${GITHUB_RUN_ID:?must run in GitHub Actions}"
required_reviewer="${OPENBAO_REQUIRED_REVIEWER:-kazan555}"
expected_environment="openbao-${environment}"

[[ "$repository" == appolon1908-hue/Codestra-OpenBao ]]
[[ "$required_reviewer" == kazan555 ]]
approvals="$(gh api "repos/${repository}/actions/runs/${run_id}/approvals")"
jq -e \
  --arg reviewer "$required_reviewer" \
  --arg environment "$expected_environment" '
  any(.;
    .state == "approved" and
    (.user.login // .reviewer.login) == $reviewer and
    any(.environments[]?; .name == $environment)
  )
' <<<"$approvals" >/dev/null

echo 'OPENBAO_PROTECTED_ENVIRONMENT_APPROVAL=PASS'
echo "OPENBAO_APPROVER=${required_reviewer}"
