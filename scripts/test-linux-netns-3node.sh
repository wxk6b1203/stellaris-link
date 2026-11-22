#!/usr/bin/env bash
set -euo pipefail

# Real 3-node Linux TUN/LSA transit test using three network namespaces.
# Requires root and a Linux binary matching the host architecture.
[[ $EUID -eq 0 ]] || { echo "run as root (needs netns + TUN)" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing Linux binary: $BIN" >&2; exit 1; }
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
DIR="${DIR:-/tmp/stellaris-3node}"
rm -rf "$DIR"; mkdir -p "$DIR"/{a,b,c}-state
cleanup() {
  kill "${A_PID:-}" "${B_PID:-}" "${C_PID:-}" 2>/dev/null || true
  for ns in sa sb sc; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT
for ns in sa sb sc; do ip netns del "$ns" 2>/dev/null || true; ip netns add "$ns"; ip netns exec "$ns" ip link set lo up; done
ip link add va type veth peer name vb1
ip link set va netns sa
ip link set vb1 netns sb
ip link add vb2 type veth peer name vc
ip link set vb2 netns sb
ip link set vc netns sc
ip netns exec sa ip addr add 10.200.0.1/24 dev va
ip netns exec sb ip addr add 10.200.0.2/24 dev vb1
ip netns exec sb ip addr add 10.201.0.2/24 dev vb2
ip netns exec sc ip addr add 10.201.0.3/24 dev vc
for ns_dev in 'sa va' 'sb vb1' 'sb vb2' 'sc vc'; do set -- $ns_dev; ip netns exec "$1" ip link set "$2" up; done

cat > "$DIR/a.toml" <<'TOML'
[node]
name = "a"
state_dir = "/tmp/stellaris-3node/a-state"
overlay_ip = "10.111.0.1"
[network]
name = "three-node"
cidr = "10.111.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46101
advertise = ["10.200.0.1:46101"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:0"
TOML
cat > "$DIR/b.toml" <<'TOML'
[node]
name = "b"
state_dir = "/tmp/stellaris-3node/b-state"
overlay_ip = "10.111.0.2"
[network]
name = "three-node"
cidr = "10.111.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46102
advertise = ["10.200.0.2:46102", "10.201.0.2:46102"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:0"
TOML
cat > "$DIR/c.toml" <<'TOML'
[node]
name = "c"
state_dir = "/tmp/stellaris-3node/c-state"
overlay_ip = "10.111.0.3"
[network]
name = "three-node"
cidr = "10.111.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46103
advertise = ["10.201.0.3:46103"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:0"
TOML
A_ID=$("$BIN" --config "$DIR/a.toml" --print-id)
B_ID=$("$BIN" --config "$DIR/b.toml" --print-id)
C_ID=$("$BIN" --config "$DIR/c.toml" --print-id)
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.111.0.2"
advertised = ["10.111.0.0/16"]
addrs = ["10.200.0.2:46102"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A_ID"
overlay_ip = "10.111.0.1"
addrs = ["10.200.0.1:46101"]
[[peers]]
name = "c"
endpoint_id = "$C_ID"
overlay_ip = "10.111.0.3"
addrs = ["10.201.0.3:46103"]
TOML
cat >> "$DIR/c.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B_ID"
overlay_ip = "10.111.0.2"
advertised = ["10.111.0.0/16"]
addrs = ["10.201.0.2:46102"]
TOML
ip netns exec sa "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec sb "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
ip netns exec sc "$BIN" --config "$DIR/c.toml" > "$DIR/c.log" 2>&1 & C_PID=$!
sleep 6
echo "--- ping A -> C ---"
ip netns exec sa ping -4 -c 3 -W 2 10.111.0.3
echo "--- ping C -> A ---"
ip netns exec sc ping -4 -c 3 -W 2 10.111.0.1
echo "--- ping A -> C 1000 bytes ---"
ip netns exec sa ping -4 -c 3 -s 1000 -W 2 10.111.0.3
echo "OK: real 3-node Linux TUN/LSA transit works."
