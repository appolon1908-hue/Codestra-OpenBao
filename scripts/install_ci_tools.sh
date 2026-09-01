#!/usr/bin/env bash
set -Eeuo pipefail

install_root="${OPENBAO_CI_TOOL_DIR:-${RUNNER_TEMP:-/tmp}/codestra-openbao-tools}"
bin_dir="$install_root/bin"
download_dir="$install_root/downloads"
mkdir -p "$bin_dir" "$download_dir"

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'Only the reviewed linux/amd64 CI toolchain is supported.' >&2
  exit 2
}

fetch_and_verify() {
  local url="$1" expected="$2" archive="$3"
  if [[ ! -f "$archive" ]]; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 4 \
      --output "$archive" "$url"
  fi
  printf '%s  %s\n' "$expected" "$archive" | sha256sum -c - >/dev/null
}

install_gitleaks() {
  local version=8.30.1
  local archive="$download_dir/gitleaks_${version}_linux_x64.tar.gz"
  fetch_and_verify \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" \
    "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" \
    "$archive"
  tar -xzf "$archive" -C "$bin_dir" gitleaks
  [[ "$($bin_dir/gitleaks version)" == "$version" ]]
}

install_syft() {
  local version=1.51.1
  local archive="$download_dir/syft_${version}_linux_amd64.tar.gz"
  fetch_and_verify \
    "https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_linux_amd64.tar.gz" \
    "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3" \
    "$archive"
  tar -xzf "$archive" -C "$bin_dir" syft
  [[ "$($bin_dir/syft version -o json | jq -r .version)" == "$version" ]]
}

install_trivy() {
  local version=0.74.0
  local archive="$download_dir/trivy_${version}_Linux-64bit.tar.gz"
  fetch_and_verify \
    "https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_Linux-64bit.tar.gz" \
    "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a" \
    "$archive"
  tar -xzf "$archive" -C "$bin_dir" trivy
  "$bin_dir/trivy" --version | grep -Fqx "Version: ${version}"
}

if (( $# == 0 )); then
  set -- gitleaks syft trivy
fi
for tool in "$@"; do
  case "$tool" in
    gitleaks) install_gitleaks ;;
    syft) install_syft ;;
    trivy) install_trivy ;;
    *) echo "Unsupported CI tool: $tool" >&2; exit 2 ;;
  esac
done

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$bin_dir" >> "$GITHUB_PATH"
else
  printf 'OPENBAO_CI_TOOL_PATH=%s\n' "$bin_dir"
fi
