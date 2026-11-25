#!/usr/bin/env bash
set -euo pipefail
# Controller-signed membership credential demo.
#   - node "a" is pre-registered in the controller config, so it receives a
#     credential as soon as it enrolls;
#   - node "b" is unknown, so its signed /v1/enroll is queued for approval and
#     an administrator approves it through POST /v1/admissions/{node}/approve.
# Both agents persist state_dir/credential.json and complete an authenticated
# iroh handshake.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT/target/debug/stellaris-agent"
CTRL="$ROOT/target/debug/stellaris-controller"
[[ -x "$AGENT" && -x "$CTRL" ]] || { echo "build first: cargo build -p stellaris-agent --bins" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-credential.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 46000 ))
CTRL_API=$BASE; A_API=$((BASE+1)); B_API=$((BASE+2)); A_PORT=$((BASE+10)); B_PORT=$((BASE+11))
SECRET="member-secret"; ADMIN="admin-secret"

cleanup() {
  for p in "${A_PID:-}" "${B_PID:-}" "${CTRL_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  rm -rf "$TMP"
}
if [[ "${KEEP:-0}" != "1" ]]; then trap cleanup EXIT; fi

cat > "$TMP/ctrl.toml" <<TOML
[node]
name = "ctrl"
role = "controller"
state_dir = "$TMP/ctrl-state"
overlay_ip = "10.112.0.254"

[network]
name = "credential-demo"
cidr = "10.112.0.0/16"

[control]
bind = "127.0.0.1:$CTRL_API"
secret = "$SECRET"
admin_secret = "$ADMIN"
credential_ttl_secs = 600
TOML
CTRL_ID=$("$CTRL" --config "$TMP/ctrl.toml" --print-id)

mkagent() {
  local n=$1 api=$2 port=$3 ip=$4
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$TMP/$n-state"
overlay_ip = "$ip"

[network]
name = "credential-demo"
cidr = "10.112.0.0/16"

[network.auth]
mode = "controller"

[control]
url = "http://127.0.0.1:$CTRL_API"
secret = "$SECRET"
controller_keys = ["$CTRL_ID"]
credential_ttl_secs = 600

[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = ["127.0.0.1:$port"]

[api]
bind = "127.0.0.1:$api"
TOML
}
mkagent a "$A_API" "$A_PORT" 10.112.0.1
mkagent b "$B_API" "$B_PORT" 10.112.0.2

A_ID=$(ROOT="$ROOT" "$AGENT" --config "$TMP/a.toml" --print-id)
B_ID=$(ROOT="$ROOT" "$AGENT" --config "$TMP/b.toml" --print-id)
cat >> "$TMP/ctrl.toml" <<TOML

[[control.members]]
node_id = "$A_ID"
overlay_ip = "10.112.0.1"
capabilities = ["member"]
TOML
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.112.0.2"
addrs = ["127.0.0.1:$B_PORT"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.112.0.1"
addrs = ["127.0.0.1:$A_PORT"]
TOML

RUST_LOG=info "$CTRL" --config "$TMP/ctrl.toml" > "$TMP/ctrl.log" 2>&1 & CTRL_PID=$!
READY=""
for _ in $(seq 1 100); do
  if curl -fsS --max-time 2 -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$CTRL_API/v1/status" >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 0.1
done
[[ -n "$READY" ]] || { echo "FAIL: controller did not start" >&2; tail -20 "$TMP/ctrl.log" >&2; exit 1; }

"$AGENT" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$AGENT" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!

# b has no member entry yet: wait for its signed enrollment to be queued, then approve it.
PENDING=""
for _ in $(seq 1 150); do
  PENDING=$(curl -fsS --max-time 2 -H "x-stellaris-secret: $ADMIN" \
    "http://127.0.0.1:$CTRL_API/v1/admissions" 2>/dev/null \
    | python3 -c 'import json,sys;print(" ".join(p["node"] for p in json.load(sys.stdin)["pending"]))' 2>/dev/null \
    || echo "")
  [[ " $PENDING " == *" $B_ID "* ]] && break
  sleep 0.1
done
[[ " $PENDING " == *" $B_ID "* ]] || {
  echo "FAIL: b did not queue a signed enrollment (pending: ${PENDING:-none})" >&2
  tail -20 "$TMP/b.log" >&2; exit 1; }
echo "b queued for approval ($B_ID)"
curl -fsS --max-time 10 -H "x-stellaris-secret: $ADMIN" -H 'content-type: application/json' \
  -d '{"prefixes":[],"capabilities":["member"]}' \
  "http://127.0.0.1:$CTRL_API/v1/admissions/$B_ID/approve" >/dev/null
echo "b approved"

for _ in $(seq 1 200); do
  [[ -f "$TMP/a-state/credential.json" && -f "$TMP/b-state/credential.json" ]] && break
  sleep 0.1
done
for n in a b; do
  [[ -f "$TMP/$n-state/credential.json" ]] || {
    echo "FAIL: $n did not store a credential" >&2
    tail -20 "$TMP/$n.log" >&2; exit 1; }
  python3 - "$TMP/$n-state/credential.json" <<'PY'
import json, sys
signed = json.load(open(sys.argv[1]))
cred = signed["credential"]
print(f"  {cred['node'][:12]}... overlay={cred['overlay_ip']} network={cred['network']} issuer={signed['issuer'][:12]}...")
PY
done

CONNECTED=""
for _ in $(seq 1 150); do
  if curl -fsS --max-time 2 "http://127.0.0.1:$A_API/v1/peers" 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(p["name"]=="b" and p["connected"] for p in d) else 1)'; then
    CONNECTED=1; break
  fi
  sleep 0.1
done
if [[ -z "$CONNECTED" ]]; then
  echo "FAIL: credentialed peer b did not connect" >&2
  tail -20 "$TMP/a.log" >&2
  tail -20 "$TMP/b.log" >&2
  exit 1
fi
echo "OK: controller-issued credentials enroll a pre-registered node and an approved node; they connect."
