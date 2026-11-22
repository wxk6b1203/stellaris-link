#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-iroh-ctrl.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 28000 ))
CTRL_API=$BASE
CTRL_IROH=$((BASE + 1))
MEMBER_API=$((BASE + 2))

cleanup() {
  [[ -n "${CTRL_PID:-}" ]] && kill "$CTRL_PID" 2>/dev/null || true
  [[ -n "${MEMBER_PID:-}" ]] && kill "$MEMBER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

cat > "$TMP/controller.toml" <<TOML
[node]
name = "ctrl"
role = "controller"
state_dir = "$TMP/ctrl-state"

[network]
name = "iroh-ctrl-demo"
cidr = "10.104.0.0/16"

[control]
bind = "127.0.0.1:$CTRL_API"
secret = "demo-secret"
epoch = 42
iroh_port = $CTRL_IROH

[transport]
disable_relay = true

[api]
bind = "127.0.0.1:0"
TOML

CID="$("$ROOT/target/debug/stellaris-controller" --config "$TMP/controller.toml" --print-id)"
echo "controller endpoint: $CID"

cat > "$TMP/member.toml" <<TOML
[node]
name = "member"
state_dir = "$TMP/member-state"
overlay_ip = "10.104.0.1"

[network]
name = "iroh-ctrl-demo"
cidr = "10.104.0.0/16"

[control]
endpoint_id = "$CID"
addrs = ["127.0.0.1:$CTRL_IROH"]
secret = "demo-secret"

[transport]
disable_relay = true

[api]
bind = "127.0.0.1:$MEMBER_API"
TOML

"$ROOT/target/debug/stellaris-controller" --config "$TMP/controller.toml" > "$TMP/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
"$ROOT/target/debug/stellaris-agent" --config "$TMP/member.toml" > "$TMP/member.log" 2>&1 & MEMBER_PID=$!
sleep 5

echo "--- controller log ---"; cat "$TMP/ctrl.log"
echo "--- member log ---"; cat "$TMP/member.log"
echo "--- controller status ---"
STATUS="$(curl -s -H 'x-stellaris-secret: demo-secret' "http://127.0.0.1:$CTRL_API/v1/status")"
echo "$STATUS"
if [[ "$STATUS" != *'"acks":1'* ]]; then
  echo "FAIL: expected one ACK over iroh" >&2
  exit 1
fi
if ! grep -q 'applied controller routes' "$TMP/member.log"; then
  echo "FAIL: member did not apply controller snapshot" >&2
  exit 1
fi
echo "OK: controller/member communicated over iroh control protocol."
