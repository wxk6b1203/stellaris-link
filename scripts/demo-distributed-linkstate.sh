#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-ls3.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 24000 ))
A_API=$((BASE)); B_API=$((BASE + 1)); C_API=$((BASE + 2))
A_PORT=$((BASE + 10)); B_PORT=$((BASE + 11)); C_PORT=$((BASE + 12))

cleanup() {
  for p in "${A_PID:-}" "${B_PID:-}" "${C_PID:-}"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

for n in a b c; do
  api=$([ "$n" = a ] && echo "$A_API" || ([ "$n" = b ] && echo "$B_API" || echo "$C_API"))
  port=$([ "$n" = a ] && echo "$A_PORT" || ([ "$n" = b ] && echo "$B_PORT" || echo "$C_PORT"))
  ip=$([ "$n" = a ] && echo 10.101.0.1 || ([ "$n" = b ] && echo 10.101.0.2 || echo 10.101.0.3))
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$TMP/$n-state"
overlay_ip = "$ip"
zone = "az-a"

[network]
name = "ls3-demo"
cidr = "10.101.0.0/16"

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
done

A_ID="$("$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" --print-id)"
B_ID="$("$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" --print-id)"
C_ID="$("$ROOT/target/debug/stellaris-agent" --config "$TMP/c.toml" --print-id)"

cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.101.0.2"
addrs = ["127.0.0.1:$B_PORT"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.101.0.1"
addrs = ["127.0.0.1:$A_PORT"]
[[peers]]
name = "c"
endpoint_id = "$C_ID"
overlay_ip = "10.101.0.3"
addrs = ["127.0.0.1:$C_PORT"]
TOML
cat >> "$TMP/c.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.101.0.2"
addrs = ["127.0.0.1:$B_PORT"]
TOML

sync
sleep 1
"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/c.toml" > "$TMP/c.log" 2>&1 & C_PID=$!

for _ in $(seq 1 30); do
  if "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" status >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done
sleep 4

echo "--- A peers (c should be auto-discovered) ---"
"$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" peer list
if ! "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" peer list \
   | grep -q "$C_ID"; then
  echo "FAIL: c was not auto-discovered via LSA" >&2
  exit 1
fi
echo "--- A RIB ---"
"$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" route list --view rib

if "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" route list --view rib \
   | grep -q '10.101.0.3/32'; then
  echo "OK: distributed LSA route a -> b -> c is present."
else
  echo "FAIL: c's /32 was not learned via LSA" >&2
  exit 1
fi

if [[ "${TEST_FAILOVER:-0}" == "1" ]]; then
  echo "--- killing c; expecting a to withdraw c's link-state route ---"
  kill "$C_PID" 2>/dev/null || true
  # heartbeat timeout is ~7s; wait a little longer.
  sleep 10
  if "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" route list --view rib \
     | grep -q '10.101.0.3/32'; then
    echo "FAIL: stale link-state route survived c failure" >&2
    echo "--- a.log ---"; tail -40 "$TMP/a.log"
    echo "--- b.log ---"; tail -20 "$TMP/b.log"
    exit 1
  fi
  echo "OK: link-state route withdrawn after c failure."
fi
