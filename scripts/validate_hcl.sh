#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image='ghcr.io/openbao/openbao@sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff'
verify_dir="$(mktemp -d)"

cleanup() {
  docker stop codestra-openbao-config-verify >/dev/null 2>&1 || true
  find "$verify_dir" -type f -delete
  find "$verify_dir" -depth -type d -empty -delete
}
trap cleanup EXIT
chmod 755 "$verify_dir"

for environment in development test staging production; do
  python3 "$repo_root/scripts/render_openbao_config.py" "$environment" \
    --output "$verify_dir/$environment.hcl"
done
diff -u "$repo_root/openbao/openbao.hcl" "$verify_dir/production.hcl"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$verify_dir/ca-key" -out "$verify_dir/ca-cert" -days 1 \
  -subj '/CN=Codestra OpenBao validation CA' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$verify_dir/server-key" -out "$verify_dir/server-csr" \
  -subj '/CN=codestra-bao-production-01' \
  -addext 'subjectAltName=DNS:codestra-bao-production-01,DNS:localhost,IP:127.0.0.1' \
  >/dev/null 2>&1
printf '%s\n' \
  'subjectAltName=DNS:codestra-bao-production-01,DNS:localhost,IP:127.0.0.1' \
  'extendedKeyUsage=serverAuth' > "$verify_dir/server-ext"
openssl x509 -req -in "$verify_dir/server-csr" \
  -CA "$verify_dir/ca-cert" -CAkey "$verify_dir/ca-key" -CAcreateserial \
  -out "$verify_dir/server-cert" -days 1 -extfile "$verify_dir/server-ext" \
  >/dev/null 2>&1
chmod 644 "$verify_dir"/*
mkdir "$verify_dir/data"
chmod 777 "$verify_dir/data"
mkdir "$verify_dir/plugins"
chmod 755 "$verify_dir/plugins"

set +e
timeout --signal=TERM 8s docker run --rm --cap-drop ALL \
  --user "$(id -u):$(id -g)" \
  --entrypoint bao \
  --name codestra-openbao-config-verify \
  -v "$repo_root/openbao/openbao.hcl:/openbao/config/openbao.hcl:ro" \
  -v "$verify_dir/data:/openbao/data" \
  -v "$verify_dir/plugins:/openbao/plugins:ro" \
  -v "$verify_dir/server-cert:/run/secrets/openbao-server-cert:ro" \
  -v "$verify_dir/server-key:/run/secrets/openbao-server-key:ro" \
  -v "$verify_dir/ca-cert:/run/secrets/codestra-client-ca:ro" \
  "$image" server -config=/openbao/config/openbao.hcl \
  >"$verify_dir/server.log" 2>&1
server_status=$?
set -e
if [[ "$server_status" != 124 && "$server_status" != 143 ]]; then
  echo "OpenBao server configuration validation failed with status ${server_status}." >&2
  sed -n '1,80p' "$verify_dir/server.log" >&2
  exit "$server_status"
fi
grep -q 'OpenBao server started' "$verify_dir/server.log"

mkdir "$verify_dir/policies"
chmod 777 "$verify_dir/policies"
cp -R "$repo_root/openbao/policies/." "$verify_dir/policies/"
find "$verify_dir/policies" -type d -exec chmod 777 {} +
find "$verify_dir/policies" -type f -exec chmod 666 {} +
docker run --rm --user root --entrypoint sh \
  -v "$verify_dir/policies:/policies" "$image" -Eeuc '
    find /policies -type f -name "*.hcl" -print0 |
      while IFS= read -r -d "" policy; do bao policy fmt "$policy" >/dev/null; done
  '
diff -ru "$repo_root/openbao/policies" "$verify_dir/policies"

echo 'OPENBAO_HCL_VALIDATION=PASS'
