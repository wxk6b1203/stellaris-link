#!/usr/bin/env bash
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"; CTRL="${CTRL:-$(pwd)/target/release/stellaris-controller}"; DIR="${DIR:-/tmp/stellaris-3ctrl}"
rm -rf "$DIR"; mkdir -p "$DIR"
cleanup(){ kill ${CTRL_PID:-} ${A_PID:-} ${B_PID:-} ${C_PID:-} 2>/dev/null || true; for ns in sa sb sc; do ip netns del $ns 2>/dev/null || true; done; if [ "${KEEP:-0}" != 1 ]; then rm -rf $DIR; fi; }
trap cleanup EXIT
ping_ok(){
  local ns=$1; shift
  if ! ip netns exec "$ns" ping -4 -c 3 -W 2 "$@" >/dev/null 2>&1; then
    echo "FAIL: ping from $ns to $*" >&2
    for f in "$DIR"/{a,b,c}.log "$DIR"/ctrl.log; do [ -f "$f" ] && { echo "--- $f"; tail -20 "$f"; }; done
    exit 1
  fi
}
for ns in sa sb sc; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip netns exec $ns ip link set lo up; done
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
name="ctun"
cidr="10.115.0.0/16"
[control]
bind="0.0.0.0:46200"
secret="ctrl-secret"
epoch=5
[transport]
disable_relay=true
[api]
bind="127.0.0.1:46210"
TOML
for n in a b c; do
 case $n in a) ip=10.115.0.1; port=46211; adv=10.200.0.1; url=http://10.200.0.2:46200;; b) ip=10.115.0.2; port=46212; adv=10.200.0.2; url=http://10.200.0.2:46200;; c) ip=10.115.0.3; port=46213; adv=10.201.0.3; url=http://10.200.0.2:46200;; esac
 cat > "$DIR/$n.toml" <<TOML
[node]
name="$n"
state_dir="$DIR/$n-state"
overlay_ip="$ip"
[network]
name="ctun"
cidr="10.115.0.0/16"
[control]
url="$url"
secret="ctrl-secret"
discover_members=false
[transport]
relay_urls=[]
disable_relay=true
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
bind="127.0.0.1:46221"
TOML
done
A=$($BIN --config "$DIR/a.toml" --print-id); B=$($BIN --config "$DIR/b.toml" --print-id); C=$($BIN --config "$DIR/c.toml" --print-id)
# b forwards a<->c traffic, so it needs the transit capability; plain
# members may only source their own overlay/prefixes.
cat >> "$DIR/controller.toml" <<TOML

[[control.members]]
node_id = "$A"
overlay_ip = "10.115.0.1"
capabilities = ["member"]

[[control.members]]
node_id = "$B"
overlay_ip = "10.115.0.2"
capabilities = ["member", "transit"]

[[control.members]]
node_id = "$C"
overlay_ip = "10.115.0.3"
capabilities = ["member"]
TOML
cat >> "$DIR/a.toml" <<TOML
[[peers]]
name="b"
endpoint_id="$B"
overlay_ip="10.115.0.2"
advertised=["10.115.0.0/16"]
addrs=["10.200.0.2:46212"]
TOML
cat >> "$DIR/b.toml" <<TOML
[[peers]]
name="a"
endpoint_id="$A"
overlay_ip="10.115.0.1"
addrs=["10.200.0.1:46211"]
[[peers]]
name="c"
endpoint_id="$C"
overlay_ip="10.115.0.3"
addrs=["10.201.0.3:46213"]
TOML
cat >> "$DIR/c.toml" <<TOML
[[peers]]
name="b"
endpoint_id="$B"
overlay_ip="10.115.0.2"
advertised=["10.115.0.0/16"]
addrs=["10.200.0.2:46212"]
TOML
ip netns exec sc ip route add 10.200.0.0/24 via 10.201.0.2
ip netns exec sb "$CTRL" --config "$DIR/controller.toml" > "$DIR/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
ip netns exec sa env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::control_client=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec sb env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::control_client=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
ip netns exec sc env RUST_LOG=stellaris_agent::dataplane=debug,stellaris_agent::control_client=debug,stellaris_agent::transport=debug "$BIN" --config "$DIR/c.toml" > "$DIR/c.log" 2>&1 & C_PID=$!
sleep 8
echo '--- routes ---'
for ns in sa sb sc; do echo "== $ns"; ip netns exec $ns ip route; ip netns exec $ns ip route get 10.115.0.1 2>&1 || true; done
echo '--- tcpdump C tun ---'
ip netns exec sc tcpdump -i stellaris0 -n -c 10 > "$DIR/c.tcp" 2>&1 & TCP_PID=$!
sleep 1
ping_ok sa 10.115.0.3
ping_ok sc 10.115.0.1
ping_ok sa -s 1000 10.115.0.3
sleep 1
kill $TCP_PID 2>/dev/null || true
cat "$DIR/c.tcp"
echo '--- B tcpdump tun ---'
ip netns exec sb tcpdump -i stellaris0 -n -c 10 > "$DIR/b.tcp" 2>&1 & TCP_PID=$!
ping_ok sc 10.115.0.1
sleep 1
kill $TCP_PID 2>/dev/null || true
cat "$DIR/b.tcp"
echo '--- logs ---'
for f in "$DIR"/{a,b,c}.log; do echo ===$f; grep -E 'inbound mesh|dropped|spoofed|no transit|deliver|forward' "$f" | tail -20; done
ip netns exec sb curl -fsS -H 'x-stellaris-secret: ctrl-secret' http://127.0.0.1:46200/v1/status >/dev/null
echo "OK: 3-node controller TUN/LSA/transit test passed (ping + status asserted)."
