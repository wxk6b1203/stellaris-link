#!/usr/bin/env bash
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
DIR="${DIR:-/tmp/stellaris-exit-nat}"
rm -rf "$DIR"; mkdir -p "$DIR"
cleanup(){ kill ${A_PID:-} ${B_PID:-} ${UDP_PID:-} 2>/dev/null || true; for ns in sa sb sc; do ip netns del $ns 2>/dev/null || true; done; [ "${KEEP:-0}" = 1 ] || rm -rf "$DIR"; }
trap cleanup EXIT
for ns in sa sb sc; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip netns exec $ns ip link set lo up; done
# underlay: A -- B -- external C
ip link add va type veth peer name vb1; ip link set va netns sa; ip link set vb1 netns sb
ip link add vb2 type veth peer name vc; ip link set vb2 netns sb; ip link set vc netns sc
ip netns exec sa ip addr add 10.200.0.1/24 dev va
ip netns exec sb ip addr add 10.200.0.2/24 dev vb1
ip netns exec sb ip addr add 10.201.0.2/24 dev vb2
ip netns exec sc ip addr add 10.201.0.3/24 dev vc
ip netns exec sc ip addr add 192.0.2.2/24 dev lo
for nd in 'sa va' 'sb vb1' 'sb vb2' 'sc vc'; do set -- $nd; ip netns exec $1 ip link set $2 up; done
ip netns exec sc ip route add 10.200.0.0/24 via 10.201.0.2
ip netns exec sb ip route add 192.0.2.0/24 via 10.201.0.3 dev vb2
cat > "$DIR/a.toml" <<TOML
[node]
name="a"
state_dir="$DIR/a-state"
overlay_ip="10.115.0.1"
[network]
name="exitnat"
cidr="10.115.0.0/16"
[network.auth]
mode="psk"
secret="exit-secret"
[transport]
relay_urls=[]
disable_relay=true
listen_port=46411
bind_ip="10.200.0.1"
advertise=["10.200.0.1:46411"]
[dataplane]
enabled=true
tun_name="stellaris0"
mtu=1100
[api]
bind="127.0.0.1:46421"
TOML
cat > "$DIR/b.toml" <<TOML
[node]
name="b"
state_dir="$DIR/b-state"
overlay_ip="10.115.0.2"
[network]
name="exitnat"
cidr="10.115.0.0/16"
[network.auth]
mode="psk"
secret="exit-secret"
[transport]
relay_urls=[]
disable_relay=true
listen_port=46412
bind_ip="10.200.0.2"
advertise=["10.200.0.2:46412"]
[dataplane]
enabled=true
tun_name="stellaris0"
mtu=1100
advertise=["0.0.0.0/0"]
nat=true
[api]
bind="127.0.0.1:46422"
TOML
A=$($BIN --config "$DIR/a.toml" --print-id); B=$($BIN --config "$DIR/b.toml" --print-id)
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name="b"
endpoint_id="$B"
overlay_ip="10.115.0.2"
advertised=["0.0.0.0/0"]
addrs=["10.200.0.2:46412"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name="a"
endpoint_id="$A"
overlay_ip="10.115.0.1"
addrs=["10.200.0.1:46411"]
TOML
ip netns exec sa env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec sb env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::gateway=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
sleep 8
ip netns exec sa ip route get 192.0.2.2 || true
echo '--- routes ---'
for ns in sa sb sc; do echo "== $ns"; ip netns exec $ns ip route; ip netns exec $ns ip -4 addr show stellaris0 2>&1 || true; done
echo '--- nat ---'
ip netns exec sb iptables -t nat -S POSTROUTING
echo '--- ping external via exit ---'
set +e
ip netns exec sa ping -4 -c 3 -W 2 192.0.2.2
PING_RC=$?
set -e
echo '--- NAT mapping consistency ---'
cat > "$DIR/udp_server.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("192.0.2.2", 9999))
for _ in range(3):
    data, peer = s.recvfrom(2048)
    print(f"{peer[0]}:{peer[1]} {data.decode()}")
s.close()
PY
ip netns exec sc python3 "$DIR/udp_server.py" > "$DIR/udp_server.out" 2>&1 & UDP_PID=$!
sleep 1
ip netns exec sa python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(3):
    s.sendto(f"udp-{i}".encode(), ("192.0.2.2", 9999))
    time.sleep(0.1)
s.close()
PY
wait "$UDP_PID" || true
UDP_PID=
cat "$DIR/udp_server.out"
python3 - "$DIR/udp_server.out" <<'PY'
import sys
lines = [line.split()[0] for line in open(sys.argv[1]) if line.strip()]
assert len(lines) == 3, lines
assert len(set(lines)) == 1, f"NAT mapping changed: {lines}"
host, _ = lines[0].rsplit(":", 1)
assert host == "10.201.0.2", f"unexpected NAT source {host}"
print("NAT mapping consistent")
PY
echo '--- logs ---'

for f in "$DIR"/{a,b}.log; do echo "===$f"; grep -E 'inbound|outbound|NAT|nat|forward|dropped|error' "$f" | tail -30; done
if [ "$PING_RC" = 0 ]; then echo "OK: public exit + NAT44 works."; else echo "FAIL: public exit ping failed" >&2; exit 1; fi
