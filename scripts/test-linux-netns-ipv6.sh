#!/usr/bin/env bash
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
CTRL="${CTRL:-$(pwd)/target/release/stellaris-controller}"
DIR="${DIR:-/tmp/stellaris-ipv6-netns}"
rm -rf "$DIR"; mkdir -p "$DIR"
cleanup(){ kill ${CTRL_PID:-} ${A_PID:-} ${B_PID:-} ${C_PID:-} 2>/dev/null || true; for ns in sa sb sc; do ip netns del $ns 2>/dev/null || true; done; [ "${KEEP:-0}" = 1 ] || rm -rf "$DIR"; }
trap cleanup EXIT
for ns in sa sb sc; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip netns exec $ns ip link set lo up; ip netns exec $ns sysctl -qw net.ipv6.conf.all.forwarding=1; done
ip link add va type veth peer name vb1; ip link set va netns sa; ip link set vb1 netns sb
ip link add vb2 type veth peer name vc; ip link set vb2 netns sb; ip link set vc netns sc
ip netns exec sa ip addr add 10.200.0.1/24 dev va
ip netns exec sb ip addr add 10.200.0.2/24 dev vb1
ip netns exec sb ip addr add 10.201.0.2/24 dev vb2
ip netns exec sc ip addr add 10.201.0.3/24 dev vc
for nd in 'sa va' 'sb vb1' 'sb vb2' 'sc vc'; do set -- $nd; ip netns exec $1 ip link set $2 up; done
cat > "$DIR/controller.toml" <<TOML
[node]
name="ctrl"
role="controller"
state_dir="$DIR/ctrl-state"
[network]
name="ctun6"
cidr="fd00:115::/64"
[control]
bind="0.0.0.0:46300"
secret="ctrl-secret"
epoch=5
[transport]
disable_relay=true
[api]
bind="127.0.0.1:46310"
TOML
for n in a b c; do
 case $n in
  a) ip=fd00:115::1; port=46311; adv=10.200.0.1; url=http://10.200.0.2:46300;;
  b) ip=fd00:115::2; port=46312; adv=10.200.0.2; url=http://10.200.0.2:46300;;
  c) ip=fd00:115::3; port=46313; adv=10.201.0.3; url=http://10.200.0.2:46300;;
 esac
 cat > "$DIR/$n.toml" <<TOML
[node]
name="$n"
state_dir="$DIR/$n-state"
overlay_ip="$ip"
[network]
name="ctun6"
cidr="fd00:115::/64"
[control]
url="$url"
secret="ctrl-secret"
discover_members=false
[transport]
relay_urls=[]
disable_relay=true
disable_discovery=true
listen_port=$port
advertise=["$adv:$port"]
bind_ip="$adv"
[routing]
link_state=true
[dataplane]
enabled=true
tun_name="stellaris0"
mtu=1280
[api]
bind="127.0.0.1:46321"
TOML
done
A=$($BIN --config "$DIR/a.toml" --print-id); B=$($BIN --config "$DIR/b.toml" --print-id); C=$($BIN --config "$DIR/c.toml" --print-id)
# b forwards IPv6 traffic between a and c, so it needs transit.
cat >> "$DIR/controller.toml" <<TOML

[[control.members]]
node_id = "$A"
overlay_ip = "fd00:115::1"
capabilities = ["member"]

[[control.members]]
node_id = "$B"
overlay_ip = "fd00:115::2"
capabilities = ["member", "transit"]

[[control.members]]
node_id = "$C"
overlay_ip = "fd00:115::3"
capabilities = ["member"]
TOML
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name="b"
endpoint_id="$B"
overlay_ip="fd00:115::2"
advertised=["fd00:115::/64"]
addrs=["10.200.0.2:46312"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name="a"
endpoint_id="$A"
overlay_ip="fd00:115::1"
addrs=["10.200.0.1:46311"]
[[peers]]
name="c"
endpoint_id="$C"
overlay_ip="fd00:115::3"
addrs=["10.201.0.3:46313"]
TOML
cat >> "$DIR/c.toml" <<TOML
[[peers]]
name="b"
endpoint_id="$B"
overlay_ip="fd00:115::2"
advertised=["fd00:115::/64"]
addrs=["10.200.0.2:46312"]
TOML
ip netns exec sc ip route add 10.200.0.0/24 via 10.201.0.2
ip netns exec sb "$CTRL" --config "$DIR/controller.toml" > "$DIR/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
ip netns exec sa env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::control_client=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec sb env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::control_client=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
ip netns exec sc env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::control_client=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/c.toml" > "$DIR/c.log" 2>&1 & C_PID=$!
sleep 14
echo '--- IPv6 routes ---'
for ns in sa sb sc; do echo "== $ns"; ip netns exec $ns ip -6 addr show stellaris0 2>&1 || true; ip netns exec $ns ip -6 route; done
echo '--- ping6 A -> C ---'
ip netns exec sa ping -6 -c 3 -W 2 fd00:115::3 || true
echo '--- ping6 C -> A ---'
ip netns exec sc ping -6 -c 3 -W 2 fd00:115::1 || true
echo '--- ping6 A -> C 1000 bytes ---'
ip netns exec sa ping -6 -c 3 -s 1000 -W 2 fd00:115::3 || true
echo '--- logs ---'
for f in "$DIR"/{a,b,c}.log; do echo "===$f"; grep -E 'ipv6|inbound mesh|dropped|no transit|deliver|forward|error' "$f" | tail -30; done
if ip netns exec sa ping -6 -c 2 -W 2 fd00:115::3 >/dev/null 2>&1 && ip netns exec sc ping -6 -c 2 -W 2 fd00:115::1 >/dev/null 2>&1; then
  echo "OK: IPv6 TUN overlay bidirectional works."
else
  echo "FAIL: IPv6 ping failed" >&2; exit 1
fi
