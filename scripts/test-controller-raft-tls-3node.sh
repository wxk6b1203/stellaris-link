#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/stellaris-controller}"
[[ -x "$BIN" ]] || { echo "build first: cargo build -p stellaris-agent --bin stellaris-controller" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-raft-tls.XXXXXX")"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$TMP/ca-key.pem" -out "$TMP/ca.pem" \
  -subj "/CN=Stellaris Raft Test CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/server-key.pem" -out "$TMP/server.csr" \
  -subj "/CN=localhost" >/dev/null 2>&1
cat > "$TMP/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,DNS:localhost
EXT
openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$TMP/server.ext" -out "$TMP/server.pem" >/dev/null 2>&1
SECRET="controller-secret"; RAFT_SECRET="raft-secret"
NODE="0101010101010101010101010101010101010101010101010101010101010101"
for i in 1 2 3; do
  mkdir -p "$TMP/n$i/state" "$TMP/n$i/raft"
  BOOT=false; [[ "$i" == 1 ]] && BOOT=true
  cat > "$TMP/n$i.toml" <<TOML
[node]
name = "c$i"
role = "controller"
state_dir = "$TMP/n$i/state"
overlay_ip = "10.7.0.$i"

[network]
name = "raft-tls"
cidr = "10.7.0.0/16"

[control]
bind = "127.0.0.1:4810$i"
secret = "$SECRET"
allow_unsigned_lsa = true
raft_dir = "$TMP/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:4800$i"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $BOOT
raft_tls_cert = "$TMP/server.pem"
raft_tls_key = "$TMP/server-key.pem"
raft_tls_ca = "$TMP/ca.pem"
raft_tls_client_cert = "$TMP/server.pem"
raft_tls_client_key = "$TMP/server-key.pem"
raft_tls_require_client_cert = true

[[control.raft_peers]]
id = 1
addr = "127.0.0.1:48001"

[[control.raft_peers]]
id = 2
addr = "127.0.0.1:48002"

[[control.raft_peers]]
id = 3
addr = "127.0.0.1:48003"

[api]
bind = "127.0.0.1:4811$i"

[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101"
overlay_ip = "10.7.0.20"
prefixes = ["192.168.202.0/24"]
TOML
  RUST_LOG=info "$BIN" --config "$TMP/n$i.toml" >"$TMP/n$i.log" 2>&1 &
  PIDS+=($!)
done
status(){ curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:4810$1/v1/status"; }
for _ in $(seq 1 100); do
  for i in 1 2 3; do
    if status "$i" >/dev/null 2>&1; then
      L=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      [[ -n "$L" ]] && break 2
    fi
  done
  sleep 0.1
done
[[ -n "${L:-}" ]] || { echo "FAIL: no leader" >&2; for i in 1 2 3; do echo "--- n$i"; tail -30 "$TMP/n$i.log"; done; exit 1; }
echo "tls leader=$L"
LSA=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.202.0/24","metric":0}],"overlay_ip":"10.7.0.20","addrs":[]}))
PY
)
curl -fsS -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' -d "$LSA" "http://127.0.0.1:4810$L/v1/lsa" >/dev/null
sleep 1
curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:4810$L/v1/snapshot?node=$NODE" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("tls snapshot ok")'
echo "OK: 3-controller raft TLS LSA/snapshot with a pre-registered member works."
