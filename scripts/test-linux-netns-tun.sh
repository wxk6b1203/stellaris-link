#!/usr/bin/env bash
set -euo pipefail

# Real Linux TUN overlay test using two network namespaces.
# Requires root. BIN must be a Linux binary for this host architecture.
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-netns.XXXXXX")"
NS_A=stellaris-sa
NS_B=stellaris-sb

cleanup() {
  kill "${A_PID:-}" "${B_PID:-}" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  rm -rf "$DIR"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || { echo "run as root (needs netns + TUN)" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing Linux binary: $BIN" >&2; exit 1; }
command -v ip >/dev/null

ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add va type veth peer name vb
ip link set vb netns "$NS_B"
ip link set va netns "$NS_A"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip addr add 10.200.0.1/24 dev va
ip netns exec "$NS_B" ip addr add 10.200.0.2/24 dev vb
ip netns exec "$NS_A" ip link set va up
ip netns exec "$NS_B" ip link set vb up

cat > "$DIR/a.toml" <<TOML
[node]
name = "a"
state_dir = "$DIR/a-state"
overlay_ip = "10.111.0.1"

[network]
name = "netns-tun"
cidr = "10.111.0.0/16"

[transport]
relay_urls = []
disable_relay = true
listen_port = 46001
advertise = ["10.200.0.1:46001"]

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:4791"
TOML
cat > "$DIR/b.toml" <<TOML
[node]
name = "b"
state_dir = "$DIR/b-state"
overlay_ip = "10.111.0.2"

[network]
name = "netns-tun"
cidr = "10.111.0.0/16"

[transport]
relay_urls = []
disable_relay = true
listen_port = 46002
advertise = ["10.200.0.2:46002"]

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:4792"
TOML

A_ID=$("$BIN" --config "$DIR/a.toml" --print-id)
B_ID=$("$BIN" --config "$DIR/b.toml" --print-id)
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.111.0.2"
addrs = ["10.200.0.2:46002"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.111.0.1"
addrs = ["10.200.0.1:46001"]
TOML

ip netns exec "$NS_A" "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec "$NS_B" "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
sleep 5

echo "--- A TUN ---"
ip netns exec "$NS_A" ip -4 addr show stellaris0
echo "--- B TUN ---"
ip netns exec "$NS_B" ip -4 addr show stellaris0
echo "--- ping A -> B ---"
ip netns exec "$NS_A" ping -4 -c 3 -W 2 10.111.0.2
echo "--- ping B -> A ---"
ip netns exec "$NS_B" ping -4 -c 3 -W 2 10.111.0.1
echo "--- ping A -> B, 1000 bytes ---"
ip netns exec "$NS_A" ping -4 -c 3 -s 1000 -W 2 10.111.0.2
echo "OK: real Linux TUN overlay works."
