#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/debug/stellaris-agent"
CLI="$ROOT/target/debug/stellaris"
DEMO="${DEMO_DIR:-$ROOT/.demo}"

if [[ ! -x "$BIN" || ! -x "$CLI" ]]; then
  echo "building binaries..."
  (cd "$ROOT" && cargo build -p stellaris-agent -p stellaris-cli)
fi

# Random ports avoid colliding with stale sockets from a previous run.
API_A=$(( (RANDOM % 4000) + 20000 ))
API_B=$((API_A + 1))
IROH_A=$(( (RANDOM % 4000) + 30000 ))
IROH_B=$((IROH_A + 1))

rm -rf "$DEMO"
mkdir -p "$DEMO"

write_config() {
  local name="$1" api="$2" ipport="$3" dataplane="$4" ip="$5"
  cat > "$DEMO/$name.toml" <<TOML
[node]
name = "$name"
state_dir = "$DEMO/$name-state"
overlay_ip = "$ip"

[network]
name = "demo"
cidr = "10.7.0.0/16"

[transport]
relay_urls = []
listen_port = $ipport

[routing]
rib_mode = "full"
max_routes = 10000
ecmp_max = 8

[dataplane]
enabled = $dataplane
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:$api"
TOML
}

write_config a "$API_A" "$IROH_A" false "10.7.0.1"
write_config b "$API_B" "$IROH_B" false "10.7.0.2"

A_ID="$("$BIN" --config "$DEMO/a.toml" --print-id)"
B_ID="$("$BIN" --config "$DEMO/b.toml" --print-id)"
echo "node A: $A_ID"
echo "node B: $B_ID"

cat >> "$DEMO/a.toml" <<TOML

[[peers]]
name = "node-b"
endpoint_id = "$B_ID"
overlay_ip = "10.7.0.2"
addrs = ["127.0.0.1:$IROH_B"]
TOML
cat >> "$DEMO/b.toml" <<TOML

[[peers]]
name = "node-a"
endpoint_id = "$A_ID"
overlay_ip = "10.7.0.1"
addrs = ["127.0.0.1:$IROH_A"]
TOML

"$BIN" --config "$DEMO/a.toml" > "$DEMO/a.log" 2>&1 &
A_PID=$!
"$BIN" --config "$DEMO/b.toml" > "$DEMO/b.log" 2>&1 &
B_PID=$!
cleanup() { kill "$A_PID" "$B_PID" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 100); do
  if "$CLI" --api "http://127.0.0.1:$API_A" status >/dev/null 2>&1 \
     && "$CLI" --api "http://127.0.0.1:$API_B" status >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "--- peers A ---"
"$CLI" --api "http://127.0.0.1:$API_A" peer list
echo "--- peers B ---"
"$CLI" --api "http://127.0.0.1:$API_B" peer list

echo "--- add route on A: 10.7.0.2/32 via B ---"
"$CLI" --api "http://127.0.0.1:$API_A" route add 10.7.0.2/32 --via "$B_ID" --metric 1
"$CLI" --api "http://127.0.0.1:$API_A" route explain 10.7.0.2

echo
echo "transport-only demo running (API A=$API_A, B=$API_B)."
echo "logs: $DEMO/a.log $DEMO/b.log"
echo "press Ctrl-C to stop"
wait
