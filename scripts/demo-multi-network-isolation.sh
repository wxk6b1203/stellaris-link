#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-mnet.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 51000 ))
A_API=$BASE; B_API=$((BASE+1)); A_PORT=$((BASE+10)); B_PORT=$((BASE+11))
cleanup(){ for p in "${A_PID:-}" "${B_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

cat > "$TMP/a.toml" <<TOML
[node]
name = "a"
state_dir = "$TMP/a-state"
overlay_ip = "10.120.0.1"

[network]
name = "net-a"
id = "11111111-1111-4111-8111-111111111111"
cidr = "10.120.0.0/16"
[network.auth]
mode = "psk"
secret = "shared-but-different-network"

[transport]
relay_urls = []
disable_relay = true
listen_port = $A_PORT
advertise = ["127.0.0.1:$A_PORT"]

[api]
bind = "127.0.0.1:$A_API"
TOML
cat > "$TMP/b.toml" <<TOML
[node]
name = "b"
state_dir = "$TMP/b-state"
overlay_ip = "10.120.0.1"

[network]
name = "net-b"
id = "22222222-2222-4222-8222-222222222222"
cidr = "10.120.0.0/16"
[network.auth]
mode = "psk"
secret = "shared-but-different-network"

[transport]
relay_urls = []
disable_relay = true
listen_port = $B_PORT
advertise = ["127.0.0.1:$B_PORT"]

[api]
bind = "127.0.0.1:$B_API"
TOML
A_ID=$("$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" --print-id)
B_ID=$("$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" --print-id)
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
"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" > "$TMP/a.log" 2>&1 & A_PID=$!
"$ROOT/target/debug/stellaris-agent" --config "$TMP/b.toml" > "$TMP/b.log" 2>&1 & B_PID=$!
sleep 5
if ! grep -q 'membership authentication failed' "$TMP/a.log" && ! grep -q 'membership authentication failed' "$TMP/b.log"; then
  echo "FAIL: different-network PSK handshake was not rejected" >&2
  tail -20 "$TMP/a.log" >&2; tail -20 "$TMP/b.log" >&2
  exit 1
fi
echo "OK: different network IDs reject the same PSK."
