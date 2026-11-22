#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-psk.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 46000 ))
A_API=$BASE; B_API=$((BASE+1)); A_PORT=$((BASE+10)); B_PORT=$((BASE+11))

cleanup() {
  for p in "${A_PID:-}" "${B_PID:-}" "${C_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  rm -rf "$TMP"
}
if [[ "${KEEP:-0}" != "1" ]]; then trap cleanup EXIT; fi

mknode() {
  local n=$1 api=$2 port=$3 ip=$4 secret=$5
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$TMP/$n-state"
overlay_ip = "$ip"

[network]
name = "psk-demo"
cidr = "10.112.0.0/16"
[network.auth]
mode = "psk"
secret = "$secret"

[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = ["127.0.0.1:$port"]

[api]
bind = "127.0.0.1:$api"
TOML
}
mknode a "$A_API" "$A_PORT" 10.112.0.1 "correct-horse"
mknode b "$B_API" "$B_PORT" 10.112.0.2 "correct-horse"
mknode c "$((BASE+102))" "$((BASE+112))" 10.112.0.3 "wrong-secret"

A_ID=$(ROOT="$ROOT" "$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" --print-id)
B_ID=$(ROOT="$ROOT" "$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" --print-id)
C_ID=$(ROOT="$ROOT" "$ROOT/target/debug/stellaris-agent" --config "$TMP/c.toml" --print-id)
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.112.0.2"
addrs = ["127.0.0.1:$B_PORT"]
[[peers]]
name = "c"
endpoint_id = "$C_ID"
overlay_ip = "10.112.0.3"
addrs = ["127.0.0.1:$((BASE+112))"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.112.0.1"
addrs = ["127.0.0.1:$A_PORT"]
TOML
cat >> "$TMP/c.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.112.0.1"
addrs = ["127.0.0.1:$A_PORT"]
TOML

"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/c.toml" > "$TMP/c.log" 2>&1 & C_PID=$!
sleep 6

echo "--- A peers ---"
PEERS="$("$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$A_API" peer list)"
echo "$PEERS"
CONNECTED=$(echo "$PEERS" | grep -c '"name": "b"' || true)
if ! echo "$PEERS" | grep -q '"name": "b"' || ! echo "$PEERS" | grep -q '"connected": true'; then
  echo "FAIL: PSK-authenticated peer b did not connect" >&2
  tail -20 "$TMP/a.log" >&2
  exit 1
fi
if echo "$PEERS" | grep -q '"name": "c".*'; then
  echo "NOTE: c is present in peer list as configured, but must not be connected"
fi
if ! grep -q 'membership authentication failed' "$TMP/a.log"; then
  echo "FAIL: wrong-PSK peer c was not rejected" >&2
  tail -20 "$TMP/a.log" >&2
  exit 1
fi
echo "OK: PSK join authentication works; wrong secret rejected."
