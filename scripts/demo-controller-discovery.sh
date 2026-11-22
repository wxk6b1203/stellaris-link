#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-disc.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 32000 ))
CTRL=$BASE
A_API=$((BASE + 1)); B_API=$((BASE + 2))
A_PORT=$((BASE + 10)); B_PORT=$((BASE + 11))

cleanup() {
  for p in "${CTRL_PID:-}" "${A_PID:-}" "${B_PID:-}"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

cat > "$TMP/controller.toml" <<TOML
[node]
name = "ctrl"
role = "controller"
state_dir = "$TMP/ctrl-state"

[network]
name = "disc-demo"
cidr = "10.106.0.0/16"

[control]
bind = "127.0.0.1:$CTRL"
secret = "disc-secret"
epoch = 3

[api]
bind = "127.0.0.1:0"
TOML

for n in a b; do
  api=$([ "$n" = a ] && echo "$A_API" || echo "$B_API")
  port=$([ "$n" = a ] && echo "$A_PORT" || echo "$B_PORT")
  ip=$([ "$n" = a ] && echo 10.106.0.1 || echo 10.106.0.2)
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$TMP/$n-state"
overlay_ip = "$ip"

[network]
name = "disc-demo"
cidr = "10.106.0.0/16"

[control]
url = "http://127.0.0.1:$CTRL"
secret = "disc-secret"

[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = ["127.0.0.1:$port"]

[api]
bind = "127.0.0.1:$api"
TOML
done

"$ROOT/target/debug/stellaris-controller" --config "$TMP/controller.toml" > "$TMP/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!
sleep 6

echo "--- A log ---"; tail -8 "$TMP/a.log"
echo "--- A peers (b should be auto-discovered) ---"
PEERS="$("$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" peer list)"
echo "$PEERS"
if ! echo "$PEERS" | grep -q 'auto-'; then
  echo "FAIL: controller member auto-discovery did not create a peer" >&2
  exit 1
fi
if ! echo "$PEERS" | grep -q '"connected": true'; then
  echo "FAIL: discovered peer did not connect" >&2
  exit 1
fi
echo "OK: controller manifest auto-discovered and connected members."
