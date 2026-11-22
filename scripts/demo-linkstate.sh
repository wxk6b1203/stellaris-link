#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-linkstate.XXXXXX")"
CTRL_PORT=$(( (RANDOM % 3000) + 18000 ))
A_PORT=$(( (RANDOM % 3000) + 22000 ))
B_PORT=$((A_PORT + 1))
A_API=$(( (RANDOM % 3000) + 26000 ))
B_API=$((A_API + 1))

cleanup() {
  [[ -n "${CTRL_PID:-}" ]] && kill "$CTRL_PID" 2>/dev/null || true
  [[ -n "${A_PID:-}" ]] && kill "$A_PID" 2>/dev/null || true
  [[ -n "${B_PID:-}" ]] && kill "$B_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

cat > "$TMP/controller.toml" <<TOML
[node]
name = "ctrl"
role = "controller"
state_dir = "$TMP/ctrl-state"

[network]
name = "linkstate-demo"
cidr = "10.99.0.0/16"

[control]
bind = "127.0.0.1:$CTRL_PORT"
secret = "demo-secret"

[api]
bind = "127.0.0.1:0"
TOML

cat > "$TMP/a.toml" <<TOML
[node]
name = "a"
state_dir = "$TMP/a-state"
overlay_ip = "10.99.0.1"
zone = "az-a"

[network]
name = "linkstate-demo"
cidr = "10.99.0.0/16"

[control]
url = "http://127.0.0.1:$CTRL_PORT"
secret = "demo-secret"

[transport]
relay_urls = []
disable_relay = true
listen_port = $A_PORT

[api]
bind = "127.0.0.1:$A_API"
TOML

cat > "$TMP/b.toml" <<TOML
[node]
name = "b"
state_dir = "$TMP/b-state"
overlay_ip = "10.99.0.2"
zone = "az-a"

[network]
name = "linkstate-demo"
cidr = "10.99.0.0/16"

[control]
url = "http://127.0.0.1:$CTRL_PORT"
secret = "demo-secret"

[transport]
relay_urls = []
disable_relay = true
listen_port = $B_PORT

[dataplane]
enabled = false
advertise = ["192.168.70.0/24"]

[api]
bind = "127.0.0.1:$B_API"
TOML

A_ID="$("$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" --print-id)"
B_ID="$("$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" --print-id)"
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.99.0.2"
zone = "az-a"
addrs = ["127.0.0.1:$B_PORT"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.99.0.1"
zone = "az-a"
addrs = ["127.0.0.1:$A_PORT"]
TOML
sync
sleep 1

"$ROOT/target/debug/stellaris-controller" --config "$TMP/controller.toml" > "$TMP/ctrl.log" 2>&1 & CTRL_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!

for _ in $(seq 1 30); do
  if "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" status >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done
sleep 4

echo "--- controller ---"
cat "$TMP/ctrl.log"
echo "--- A link-state routes (192.168.70.0/24 should be via B) ---"
"$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" route list --view rib
echo "--- B link-state routes ---"
"$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$B_API" route list --view rib

if "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" route list --view rib \
   | grep -q '192.168.70.0/24'; then
  echo "OK: controller-mediated link-state route propagated."
else
  echo "FAIL: link-state route missing" >&2
  exit 1
fi
