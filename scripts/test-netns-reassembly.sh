#!/usr/bin/env bash
# Large pings cross a 1500->1280 MTU step: the destination agent must
# reassemble the fragments before ACL/delivery. Requires root/TUN.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-frag.XXXXXX")"
NS_A=stellaris-frag-a
NS_B=stellaris-frag-b
cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: $DIR retained"; return; }
  kill "${A_PID:-}" "${B_PID:-}" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  rm -rf "$DIR"
}
trap cleanup EXIT
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing binary: $BIN" >&2; exit 1; }
ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add va type veth peer name vb
ip link set vb netns "$NS_B"; ip link set va netns "$NS_A"
ip netns exec "$NS_A" ip link set lo up; ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip addr add 10.202.0.1/24 dev va
ip netns exec "$NS_B" ip addr add 10.202.0.2/24 dev vb
ip netns exec "$NS_A" ip link set va up; ip netns exec "$NS_B" ip link set vb up
cat > "$DIR/a.toml" <<TOML
[node]
name = "a"
state_dir = "$DIR/a-state"
overlay_ip = "10.113.0.1"
[network]
name = "frag"
cidr = "10.113.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46021
advertise = ["10.202.0.1:46021"]
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 600
[api]
bind = "127.0.0.1:4795"
TOML
cat > "$DIR/b.toml" <<TOML
[node]
name = "b"
state_dir = "$DIR/b-state"
overlay_ip = "10.113.0.2"
[network]
name = "frag"
cidr = "10.113.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46022
advertise = ["10.202.0.2:46022"]
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1500
[api]
bind = "127.0.0.1:4796"
TOML
A_ID=$("$BIN" --config "$DIR/a.toml" --print-id)
B_ID=$("$BIN" --config "$DIR/b.toml" --print-id)
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.113.0.2"
addrs = ["10.202.0.2:46022"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.113.0.1"
addrs = ["10.202.0.1:46021"]
TOML
ip netns exec "$NS_A" "$BIN" --config "$DIR/a.toml" >"$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec "$NS_B" "$BIN" --config "$DIR/b.toml" >"$DIR/b.log" 2>&1 & B_PID=$!
sleep 6
echo '--- large ping through the MTU step'
ip netns exec "$NS_A" ping -c 3 -W 3 -s 1000 10.113.0.2 | tail -3
REASSEMBLED=$(ip netns exec "$NS_B" curl -fsS --max-time 3 http://127.0.0.1:4796/v1/status \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["stats"]["frag_reassembled"])')
REASSEMBLED_A=$(ip netns exec "$NS_A" curl -fsS --max-time 3 http://127.0.0.1:4795/v1/status \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["stats"]["frag_reassembled"])')
[[ "$REASSEMBLED" -ge 1 ]] || { echo "FAIL: frag_reassembled=$REASSEMBLED" >&2; exit 1; }
[[ "$REASSEMBLED_A" -ge 1 ]] || { echo "FAIL: reply was not reassembled (a=$REASSEMBLED_A)" >&2; exit 1; }
grep -q "frag_reassembled" <(ip netns exec "$NS_B" curl -fsS http://127.0.0.1:4796/metrics) || {
  echo "FAIL: /metrics lacks fragment counters" >&2; exit 1; }
echo "reassembled: request_at_b=$REASSEMBLED reply_at_a=$REASSEMBLED_A"
echo "OK: application-layer reassembly verified"
