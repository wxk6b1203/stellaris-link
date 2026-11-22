#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-ctrl3.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 50000 ))
CTRL_API=$BASE
A_API=$((BASE+1)); B_API=$((BASE+2)); C_API=$((BASE+3))
A_PORT=$((BASE+11)); B_PORT=$((BASE+12)); C_PORT=$((BASE+13))
SECRET="demo-secret"
cleanup() { for p in "${CTRL_PID:-}" "${A_PID:-}" "${B_PID:-}" "${C_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

cat > "$TMP/ctrl.toml" <<TOML
[node]
name = "ctrl"
role = "controller"
state_dir = "$TMP/ctrl-state"

[network]
name = "ctrl3"
cidr = "10.114.0.0/16"

[control]
bind = "127.0.0.1:$CTRL_API"
secret = "$SECRET"
epoch = 1

[transport]
disable_relay = true

[api]
bind = "127.0.0.1:0"
TOML

mknode() {
  local n=$1 api=$2 port=$3 ip=$4
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$TMP/$n-state"
overlay_ip = "$ip"

[network]
name = "ctrl3"
cidr = "10.114.0.0/16"

[control]
url = "http://127.0.0.1:$CTRL_API"
secret = "$SECRET"

[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = ["127.0.0.1:$port"]

[routing]
link_state = true

[api]
bind = "127.0.0.1:$api"
TOML
}
mknode a "$A_API" "$A_PORT" 10.114.0.1
mknode b "$B_API" "$B_PORT" 10.114.0.2
mknode c "$C_API" "$C_PORT" 10.114.0.3

A_ID=$("$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" --print-id)
B_ID=$("$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" --print-id)
C_ID=$("$ROOT/target/debug/stellaris-agent" --config "$TMP/c.toml" --print-id)
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.114.0.2"
addrs = ["127.0.0.1:$B_PORT"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.114.0.1"
addrs = ["127.0.0.1:$A_PORT"]
[[peers]]
name = "c"
endpoint_id = "$C_ID"
overlay_ip = "10.114.0.3"
addrs = ["127.0.0.1:$C_PORT"]
TOML
cat >> "$TMP/c.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.114.0.2"
addrs = ["127.0.0.1:$B_PORT"]
TOML

"$ROOT/target/debug/stellaris-controller" --config "$TMP/ctrl.toml" > "$TMP/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/c.toml" > "$TMP/c.log" 2>&1 & C_PID=$!
sleep 7

STATUS=$(curl -s -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$CTRL_API/v1/status")
echo "controller: $STATUS"
SNAP=$(curl -s -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$CTRL_API/v1/snapshot")
MEMBERS=$(echo "$SNAP" | grep -o '"node_id"' | wc -l | tr -d ' ')
echo "snapshot members: $MEMBERS"
ROUTES=$(curl -s "http://127.0.0.1:$A_API/v1/routes" || true)
echo "a routes: $ROUTES"
if [[ "$STATUS" != *'"acks":3'* ]]; then
  echo "FAIL: expected 3 controller acks" >&2
  tail -20 "$TMP/a.log" "$TMP/b.log" "$TMP/c.log" "$TMP/ctrl.log" >&2
  exit 1
fi
if [[ "$MEMBERS" -lt 3 ]]; then
  echo "FAIL: expected 3 controller members" >&2
  exit 1
fi
if ! echo "$ROUTES" | grep -q '10.114.0.3'; then
  echo "FAIL: a did not learn c route" >&2
  exit 1
fi
echo "OK: controller + 3 members + LSA works."
