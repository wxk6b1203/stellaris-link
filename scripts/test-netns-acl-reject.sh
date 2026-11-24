#!/usr/bin/env bash
# ACL deny semantics: `deny_action = "reject"` returns ICMP admin-prohibited
# (ping fails fast), `drop` stays silent (ping times out). Requires root/TUN.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-acl.XXXXXX")"
NS_A=stellaris-acl-a
NS_B=stellaris-acl-b
cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: namespaces and $DIR retained"; return; }
  kill "${A_PID:-}" "${B_PID:-}" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  rm -rf "$DIR"
}
trap cleanup EXIT
[[ $EUID -eq 0 ]] || { echo "run as root (needs netns + TUN)" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing Linux binary: $BIN" >&2; exit 1; }
ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add va type veth peer name vb
ip link set vb netns "$NS_B"; ip link set va netns "$NS_A"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip addr add 10.201.0.1/24 dev va
ip netns exec "$NS_B" ip addr add 10.201.0.2/24 dev vb
ip netns exec "$NS_A" ip link set va up
ip netns exec "$NS_B" ip link set vb up

write_configs() {
  local deny_action=$1
  cat > "$DIR/a.toml" <<TOML
[node]
name = "a"
state_dir = "$DIR/a-state"
overlay_ip = "10.112.0.1"
[network]
name = "acl-reject"
cidr = "10.112.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46011
advertise = ["10.201.0.1:46011"]
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:4793"
TOML
  cat > "$DIR/b.toml" <<TOML
[node]
name = "b"
state_dir = "$DIR/b-state"
overlay_ip = "10.112.0.2"
[network]
name = "acl-reject"
cidr = "10.112.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46012
advertise = ["10.201.0.2:46012"]
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:4794"
[acl]
deny_action = "$deny_action"
[[acl.rules]]
name = "deny-a"
action = "deny"
direction = "inbound"
priority = 10
src = "10.112.0.1/32"
TOML
}
write_configs reject
A_ID=$("$BIN" --config "$DIR/a.toml" --print-id)
B_ID=$("$BIN" --config "$DIR/b.toml" --print-id)
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.112.0.2"
advertised = ["10.112.0.2/32"]
addrs = ["10.201.0.2:46012"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.112.0.1"
addrs = ["10.201.0.1:46011"]
TOML
start() {
  ip netns exec "$NS_A" "$BIN" --config "$DIR/a.toml" >>"$DIR/a.log" 2>&1 & A_PID=$!
  ip netns exec "$NS_B" "$BIN" --config "$DIR/b.toml" >>"$DIR/b.log" 2>&1 & B_PID=$!
  sleep 6
}
stop() { kill "$A_PID" "$B_PID" 2>/dev/null || true; wait 2>/dev/null || true; }
start

echo '--- deny_action = reject'
set +e
REJECT_OUT=$(ip netns exec "$NS_A" ping -c 2 -W 2 10.112.0.2 2>&1)
REJECT_CODE=$?
set -e
echo "$REJECT_OUT" | tail -3
[[ $REJECT_CODE -ne 0 ]] || { echo "FAIL: denied ping unexpectedly succeeded" >&2; exit 1; }
echo "$REJECT_OUT" | grep -qiE "unreachable|prohibit|filtered" || {
  echo "FAIL: no ICMP admin-prohibited indication from ping" >&2; exit 1; }
REJECTED=$(ip netns exec "$NS_B" curl -fsS --max-time 3 http://127.0.0.1:4794/v1/status \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["stats"]["acl_rejected"])')
[[ "$REJECTED" -ge 1 ]] || { echo "FAIL: acl_rejected counter=$REJECTED" >&2; exit 1; }
echo "reject ok: ping failed fast with ICMP, acl_rejected=$REJECTED"
stop

echo '--- deny_action = drop'
write_configs drop
start
set +e
DROP_OUT=$(ip netns exec "$NS_A" ping -c 2 -W 2 10.112.0.2 2>&1)
DROP_CODE=$?
set -e
echo "$DROP_OUT" | tail -3
[[ $DROP_CODE -ne 0 ]] || { echo "FAIL: dropped ping unexpectedly succeeded" >&2; exit 1; }
echo "$DROP_OUT" | grep -q "100% packet loss" || {
  echo "FAIL: silent drop did not time out" >&2; exit 1; }
echo "drop ok: silent timeout"
stop
echo "OK: ACL reject/drop semantics verified"
