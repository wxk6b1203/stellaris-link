#!/usr/bin/env bash
set -euo pipefail
# Two agents share an overlay CIDR/address but belong to different networks,
# each with its own controller. Credentials are network-scoped, so the iroh
# handshake across networks must fail even though both nodes enrolled locally.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT/target/debug/stellaris-agent"
CTRL="$ROOT/target/debug/stellaris-controller"
[[ -x "$AGENT" && -x "$CTRL" ]] || { echo "build first: cargo build -p stellaris-agent --bins" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-mnet.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 51000 ))
A_API=$BASE; B_API=$((BASE+1)); A_PORT=$((BASE+10)); B_PORT=$((BASE+11))
A_CTRL_API=$((BASE+20)); B_CTRL_API=$((BASE+21))
A_SECRET="controller-a-secret"; B_SECRET="controller-b-secret"
cleanup(){ for p in "${A_PID:-}" "${B_PID:-}" "${A_CTRL_PID:-}" "${B_CTRL_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

cat > "$TMP/ctrl-a.toml" <<TOML
[node]
name = "ctrl-a"
role = "controller"
state_dir = "$TMP/ctrl-a-state"
overlay_ip = "10.120.0.254"
[network]
name = "net-a"
id = "11111111-1111-4111-8111-111111111111"
cidr = "10.120.0.0/16"
[control]
bind = "127.0.0.1:$A_CTRL_API"
secret = "$A_SECRET"
TOML
cat > "$TMP/ctrl-b.toml" <<TOML
[node]
name = "ctrl-b"
role = "controller"
state_dir = "$TMP/ctrl-b-state"
overlay_ip = "10.120.0.253"
[network]
name = "net-b"
id = "22222222-2222-4222-8222-222222222222"
cidr = "10.120.0.0/16"
[control]
bind = "127.0.0.1:$B_CTRL_API"
secret = "$B_SECRET"
TOML
A_CTRL_ID=$("$CTRL" --config "$TMP/ctrl-a.toml" --print-id)
B_CTRL_ID=$("$CTRL" --config "$TMP/ctrl-b.toml" --print-id)

mkagent(){
  local n=$1 api=$2 port=$3 ctrl_api=$4 secret=$5 net=$6 id=$7 keys=$8
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$TMP/$n-state"
overlay_ip = "10.120.0.1"

[network]
name = "$net"
id = "$id"
cidr = "10.120.0.0/16"

[network.auth]
mode = "controller"

[control]
url = "http://127.0.0.1:$ctrl_api"
secret = "$secret"
controller_keys = ["$keys"]
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
mkagent a "$A_API" "$A_PORT" "$A_CTRL_API" "$A_SECRET" net-a "11111111-1111-4111-8111-111111111111" "$A_CTRL_ID"
mkagent b "$B_API" "$B_PORT" "$B_CTRL_API" "$B_SECRET" net-b "22222222-2222-4222-8222-222222222222" "$B_CTRL_ID"
A_ID=$("$AGENT" --config "$TMP/a.toml" --print-id)
B_ID=$("$AGENT" --config "$TMP/b.toml" --print-id)
cat >> "$TMP/ctrl-a.toml" <<TOML

[[control.members]]
node_id = "$A_ID"
overlay_ip = "10.120.0.1"
TOML
cat >> "$TMP/ctrl-b.toml" <<TOML

[[control.members]]
node_id = "$B_ID"
overlay_ip = "10.120.0.1"
TOML
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.120.0.1"
addrs = ["127.0.0.1:$B_PORT"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.120.0.1"
addrs = ["127.0.0.1:$A_PORT"]
TOML

RUST_LOG=info "$CTRL" --config "$TMP/ctrl-a.toml" > "$TMP/ctrl-a.log" 2>&1 & A_CTRL_PID=$!
RUST_LOG=info "$CTRL" --config "$TMP/ctrl-b.toml" > "$TMP/ctrl-b.log" 2>&1 & B_CTRL_PID=$!
READY=""
for _ in $(seq 1 100); do
  if curl -fsS --max-time 2 -H "x-stellaris-secret: $A_SECRET" "http://127.0.0.1:$A_CTRL_API/v1/status" >/dev/null 2>&1 \
    && curl -fsS --max-time 2 -H "x-stellaris-secret: $B_SECRET" "http://127.0.0.1:$B_CTRL_API/v1/status" >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 0.1
done
[[ -n "$READY" ]] || {
  echo "FAIL: controllers did not start" >&2
  tail -20 "$TMP/ctrl-a.log" >&2; tail -20 "$TMP/ctrl-b.log" >&2; exit 1; }
"$AGENT" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$AGENT" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!

for _ in $(seq 1 200); do
  [[ -f "$TMP/a-state/credential.json" && -f "$TMP/b-state/credential.json" ]] && break
  sleep 0.1
done
[[ -f "$TMP/a-state/credential.json" && -f "$TMP/b-state/credential.json" ]] || {
  echo "FAIL: an agent did not enroll with its own controller" >&2
  tail -20 "$TMP/a.log" >&2; tail -20 "$TMP/b.log" >&2; exit 1; }

# A missing credential also fails the handshake, so require the specific
# network-scope error after both agents have enrolled locally.
REJECTED=""
for _ in $(seq 1 150); do
  if grep -qE 'membership authentication failed.*credential network mismatch|credential network mismatch.*membership authentication failed' \
    "$TMP/a.log" "$TMP/b.log" 2>/dev/null; then
    REJECTED=1; break
  fi
  sleep 0.1
done
if [[ -z "$REJECTED" ]]; then
  echo "FAIL: cross-network credential was not rejected with a network mismatch" >&2
  tail -20 "$TMP/a.log" >&2; tail -20 "$TMP/b.log" >&2
  exit 1
fi
echo "OK: credentials issued for different network IDs are rejected at the iroh handshake."
