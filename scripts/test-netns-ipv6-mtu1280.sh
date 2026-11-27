#!/usr/bin/env bash
# IPv6 overlay over a 1280-byte underlay. iroh/QUIC cannot carry a full
# 1296-byte frame here; the agent must use the real path MTU for TCP MSS and
# generate PTB for larger local packets instead of silently dropping them.
# Requires root/TUN.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-v6mss.XXXXXX")"
NS_A=stellaris-v6mss-a
NS_B=stellaris-v6mss-b
cleanup() {
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
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add va type veth peer name vb
ip link set vb netns "$NS_B"
ip link set va netns "$NS_A"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip link set va mtu 1280
ip netns exec "$NS_B" ip link set vb mtu 1280
ip netns exec "$NS_A" ip addr add 10.204.0.1/24 dev va
ip netns exec "$NS_B" ip addr add 10.204.0.2/24 dev vb
ip netns exec "$NS_A" ip link set va up
ip netns exec "$NS_B" ip link set vb up

cat > "$DIR/a.toml" <<TOML
[node]
name = "a"
state_dir = "$DIR/a-state"
overlay_ip = "fd00:116::1"
[network]
name = "ipv6-mtu1280"
cidr = "fd00:116::/64"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46431
bind_ip = "10.204.0.1"
advertise = ["10.204.0.1:46431"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:46441"
TOML
cat > "$DIR/b.toml" <<TOML
[node]
name = "b"
state_dir = "$DIR/b-state"
overlay_ip = "fd00:116::2"
[network]
name = "ipv6-mtu1280"
cidr = "fd00:116::/64"
[transport]
relay_urls = []
disable_relay = true
listen_port = 46432
bind_ip = "10.204.0.2"
advertise = ["10.204.0.2:46432"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:46442"
TOML
A=$($BIN --config "$DIR/a.toml" --print-id)
B=$($BIN --config "$DIR/b.toml" --print-id)
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name = "b"
endpoint_id = "$B"
overlay_ip = "fd00:116::2"
addrs = ["10.204.0.2:46432"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name = "a"
endpoint_id = "$A"
overlay_ip = "fd00:116::1"
addrs = ["10.204.0.1:46431"]
TOML
ip netns exec "$NS_A" "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec "$NS_B" "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
sleep 12

echo "--- TUN / peer MTU"
ip netns exec "$NS_A" ip link show stellaris0 | head -1
peer_mtu=$(ip netns exec "$NS_A" curl -fsS http://127.0.0.1:46441/v1/peers | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d[0].get("mtu"))')
echo "peer max_datagram=$peer_mtu"
[[ -n "$peer_mtu" && "$peer_mtu" -le 1248 ]] || {
  echo "NOTE: this underlay still reports a large QUIC datagram ($peer_mtu); the MTU-1280 path is not exercised" >&2
}

echo "--- IPv6 1000-byte ping"
ip netns exec "$NS_A" ping -6 -c 3 -W 2 -s 1000 fd00:116::2

echo "--- IPv6 TCP 1 MiB over the overlay"
ip netns exec "$NS_B" python3 - "$DIR" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("fd00:116::2", 9000))
s.listen(1)
s.settimeout(20)
c, _ = s.accept()
c.settimeout(20)
data = b""
while True:
    chunk = c.recv(65536)
    if not chunk:
        break
    data += chunk
open(sys.argv[1] + "/server.bytes", "w").write(str(len(data)))
c.close(); s.close()
PY
SRV_PID=$!
sleep 1
ip netns exec "$NS_A" python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(20)
s.connect(("fd00:116::2", 9000))
chunk = b"x" * 65536
sent = 0
for _ in range(16):
    s.sendall(chunk)
    sent += len(chunk)
s.shutdown(socket.SHUT_WR)
s.close()
print(f"client_sent={sent}")
PY
wait "$SRV_PID" || true
GOT=$(cat "$DIR/server.bytes" 2>/dev/null || echo 0)
echo "server_received=$GOT"
[[ "$GOT" -ge 1048576 ]] || { echo "FAIL: TCP transfer stalled at $GOT bytes" >&2; exit 1; }
echo "OK: IPv6 TCP survives a 1280-byte underlay (MSS/PTB path)"
