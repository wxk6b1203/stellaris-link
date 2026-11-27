#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/stellaris-agent}"
CTRL_BIN="${CTRL_BIN:-$ROOT/target/debug/stellaris-controller}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-tls.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 55000 ))
API=$BASE; CTRL=$((BASE+1)); MEMBER_API=$((BASE+2))
cleanup(){ for p in "${A_PID:-}" "${C_PID:-}" "${M_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done; if [[ "${KEEP:-0}" != 1 ]]; then rm -rf "$TMP"; fi; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TMP/ca-key.pem" -out "$TMP/ca.pem" \
  -subj "/CN=Stellaris Test CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$TMP/key.pem" -out "$TMP/server.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
cat > "$TMP/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EXT
openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$TMP/server.ext" -out "$TMP/cert.pem" >/dev/null 2>&1

cat > "$TMP/api.toml" <<TOML
[node]
name = "api-tls"
state_dir = "$TMP/api-state"
[network]
name = "api-tls"
cidr = "10.212.0.0/16"
[api]
bind = "127.0.0.1:$API"
token = "api-token"
tls_cert = "$TMP/cert.pem"
tls_key = "$TMP/key.pem"
TOML
"$BIN" --config "$TMP/api.toml" > "$TMP/api.log" 2>&1 & A_PID=$!

cat > "$TMP/ctrl.toml" <<TOML
[node]
name = "ctrl-tls"
role = "controller"
state_dir = "$TMP/ctrl-state"
[network]
name = "ctrl-tls"
cidr = "10.213.0.0/16"
[control]
bind = "127.0.0.1:$CTRL"
secret = "ctrl-secret"
tls_cert = "$TMP/cert.pem"
tls_key = "$TMP/key.pem"
[transport]
disable_relay = true
[api]
bind = "127.0.0.1:0"
TOML
cat > "$TMP/member.toml" <<TOML
[node]
name = "member-tls"
state_dir = "$TMP/member-state"
overlay_ip = "10.213.0.1"
[network]
name = "ctrl-tls"
cidr = "10.213.0.0/16"
[control]
url = "https://127.0.0.1:$CTRL"
secret = "ctrl-secret"
tls_ca = "$TMP/ca.pem"
[transport]
disable_relay = true
[api]
bind = "127.0.0.1:$MEMBER_API"
TOML
"$CTRL_BIN" --config "$TMP/ctrl.toml" > "$TMP/ctrl.log" 2>&1 & C_PID=$!
sleep 2
"$BIN" --config "$TMP/member.toml" > "$TMP/member.log" 2>&1 & M_PID=$!
sleep 5
if ! curl -fsS --cacert "$TMP/ca.pem" -H "Authorization: Bearer api-token" "https://127.0.0.1:$API/v1/status" >/dev/null; then
  echo "FAIL: API HTTPS" >&2; tail -20 "$TMP/api.log" >&2; exit 1
fi
if ! curl -fsS --cacert "$TMP/ca.pem" -H "x-stellaris-secret: ctrl-secret" "https://127.0.0.1:$CTRL/v1/status" >/dev/null; then
  echo "FAIL: controller HTTPS" >&2; tail -20 "$TMP/ctrl.log" >&2; exit 1
fi
if ! grep -q 'applied controller routes' "$TMP/member.log"; then
  echo "FAIL: member did not apply controller TLS snapshot" >&2; tail -20 "$TMP/member.log" >&2; exit 1
fi
echo "OK: API TLS, controller TLS, and member HTTPS snapshot work."
