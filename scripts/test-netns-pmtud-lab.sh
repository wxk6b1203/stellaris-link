#!/usr/bin/env bash
set -euo pipefail
# Chengdu netns lab: a(1500) - r1(1400) - r2(1300) - b.
# Assumes namespaces a,r1,r2,b and underlay addresses are already configured.
HOST="${HOST:?set HOST (root@...)}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/pmtud-lab}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-netns-pmtud.XXXXXX")"
cleanup(){
  ssh -o BatchMode=yes "$HOST" "ip netns exec r2 iptables -D OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP 2>/dev/null || true; for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done; rm -rf $DIR" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
ssh -o BatchMode=yes "$HOST" 'for ns in a r1 r2 b; do ip netns list | grep -q "^$ns" || { echo "missing netns $ns" >&2; exit 1; }; done'
# IPv6 addresses/routes on the same veth topology.
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ip -6 addr replace fd00:1::1/64 dev a0; ip netns exec r1 ip -6 addr replace fd00:1::2/64 dev r1a; ip netns exec r1 ip -6 addr replace fd00:2::1/64 dev r1b; ip netns exec r2 ip -6 addr replace fd00:2::2/64 dev r2a; ip netns exec r2 ip -6 addr replace fd00:3::1/64 dev r2b; ip netns exec b ip -6 addr replace fd00:3::2/64 dev b0; ip netns exec a ip -6 route replace default via fd00:1::2; ip netns exec b ip -6 route replace default via fd00:3::1; ip netns exec r1 ip -6 route replace fd00:3::/64 via fd00:2::2; ip netns exec r2 ip -6 route replace fd00:1::/64 via fd00:2::1; ip netns exec r1 sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null; ip netns exec r2 sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null'
ssh -o BatchMode=yes "$HOST" "rm -rf $DIR; mkdir -p $DIR/a-state $DIR/b-state"
cat > "$TMP/a.toml" <<TOML
[node]
name = "lab-a"
state_dir = "$DIR/a-state"
overlay_ip = "10.70.0.1"
[network]
name = "pmtud-lab"
cidr = "10.70.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 5921
bind_ip = "10.0.1.1"
advertise = ["10.0.1.1:5921"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1400
[api]
bind = "127.0.0.1:5981"
TOML
cat > "$TMP/b.toml" <<TOML
[node]
name = "lab-b"
state_dir = "$DIR/b-state"
overlay_ip = "10.70.0.2"
[network]
name = "pmtud-lab"
cidr = "10.70.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = 5922
bind_ip = "10.0.3.2"
advertise = ["10.0.3.2:5922"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1400
[api]
bind = "127.0.0.1:5982"
TOML
A_ID=$(ssh -o BatchMode=yes "$HOST" "ip netns exec a $BIN --config /dev/stdin --print-id" < "$TMP/a.toml")
B_ID=$(ssh -o BatchMode=yes "$HOST" "ip netns exec b $BIN --config /dev/stdin --print-id" < "$TMP/b.toml")
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name = "lab-b"
endpoint_id = "$B_ID"
overlay_ip = "10.70.0.2"
addrs = ["10.0.3.2:5922"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name = "lab-a"
endpoint_id = "$A_ID"
overlay_ip = "10.70.0.1"
addrs = ["10.0.1.1:5921"]
TOML
scp -q "$TMP/a.toml" "$HOST:$DIR/a.toml"; scp -q "$TMP/b.toml" "$HOST:$DIR/b.toml"
ssh -o BatchMode=yes "$HOST" "ip netns exec a nohup $BIN --config $DIR/a.toml >$DIR/a.log 2>&1 & echo \$! >$DIR/a.pid; ip netns exec b nohup $BIN --config $DIR/b.toml >$DIR/b.log 2>&1 & echo \$! >$DIR/b.pid"
sleep 8
echo '--- agent underlay path MTU / TUN ---'
peers=$(ssh -o BatchMode=yes "$HOST" 'ip netns exec a curl -fsS http://127.0.0.1:5981/v1/peers')
echo "$peers"
tun_mtu=$(ssh -o BatchMode=yes "$HOST" 'ip netns exec a ip link show stellaris0 | sed -n "s/.*mtu \([0-9]*\).*/\1/p" | head -1')
peer_mtu=$(echo "$peers" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((p.get("mtu") or 0 for p in d if p["name"]=="lab-b"),0))')
echo "peer_mtu=$peer_mtu tun_mtu=$tun_mtu"
[[ "$tun_mtu" -le "$peer_mtu" ]] || { echo "FAIL: TUN MTU exceeds peer path MTU" >&2; exit 1; }
echo '--- 2000-byte fragmented ping over overlay ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -c3 -W2 -s 2000 -M dont 10.70.0.2'
echo '--- 2 MiB TCP over overlay ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec b sh -c "cat >/tmp/srv.py <<PY
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"10.70.0.2\",8080)); s.listen(1)
c,_=s.accept(); c.sendall(b\"x\"*(2*1024*1024)); c.close(); s.close()
PY
nohup python3 /tmp/srv.py >/tmp/srv.log 2>&1 & echo \$! >/tmp/srv.pid"'
sleep 1
tcp=$(ssh -o BatchMode=yes "$HOST" 'ip netns exec a python3 - <<PY
import socket
s=socket.create_connection(("10.70.0.2",8080),5); n=0
while True:
 d=s.recv(65536)
 if not d: break
 n+=len(d)
print(n)
PY')
echo "tcp_bytes=$tcp"
[[ "$tcp" == "2097152" ]] || { echo "FAIL: TCP transfer incomplete" >&2; exit 1; }
ssh -o BatchMode=yes "$HOST" 'ip netns exec b sh -c "kill \$(cat /tmp/srv.pid) 2>/dev/null || true; rm -f /tmp/srv.py /tmp/srv.pid"'
echo '--- kernel hop-by-hop PMTU ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ip route flush cache; ip netns exec a tracepath -n 10.0.3.2' | tee "$TMP/trace"
grep -q 'pmtu 1400' "$TMP/trace"
grep -q 'pmtu 1300' "$TMP/trace"
echo '--- positive PTB: 1450 -> R1 1400, then 1378 -> R2 1300 ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ip route flush cache; ip netns exec a ping -M do -c 1 -W 2 -s 1422 10.0.3.2' >"$TMP/ptb1" 2>&1 || true
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -M do -c 2 -W 2 -s 1350 10.0.3.2' >"$TMP/ptb2" 2>&1 || true
cat "$TMP/ptb1" "$TMP/ptb2"
grep -qE 'mtu[ =]1300|mtu=1300' "$TMP/ptb2" || { echo "FAIL: no hop-2 PTB 1300" >&2; exit 1; }
echo '--- PTB blackhole at R2 ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec r2 iptables -I OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP; ip netns exec a ip route flush cache; ip netns exec a ping -M do -c 2 -W 2 -s 1350 10.0.3.2' >"$TMP/bh" 2>&1 || true
cat "$TMP/bh"
grep -q 'packet loss' "$TMP/bh" || { echo "FAIL: blackhole produced no loss" >&2; exit 1; }
grep -qE 'mtu[ =]1300|mtu=1300' "$TMP/bh" && { echo "FAIL: blackhole still returned 1300 PTB" >&2; exit 1; }
echo '--- restore PTB and recover ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec r2 iptables -D OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP; ip netns exec a ip route flush cache; ip netns exec a ping -M do -c 2 -W 2 -s 1350 10.0.3.2' >"$TMP/rec" 2>&1 || true
cat "$TMP/rec"
grep -qE 'mtu[ =]1300|mtu=1300' "$TMP/rec" || { echo "FAIL: no PTB after restore" >&2; exit 1; }
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -M do -c 2 -W 2 -s 1272 10.0.3.2'
echo '--- IPv6 hop-by-hop PMTU ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ip -6 route flush cache; ip netns exec a tracepath -6 -n fd00:3::2' | tee "$TMP/trace6"
grep -q 'pmtu 1400' "$TMP/trace6"
grep -q 'pmtu 1300' "$TMP/trace6"
echo '--- IPv6 PTB 1450 -> R1 1400, then 1300 -> R2 1300 ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ip -6 route flush cache; ip netns exec a ping -6 -I fd00:1::1 -M do -c1 -W2 -s 1450 fd00:3::2' >"$TMP/ptb6a" 2>&1 || true
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -6 -I fd00:1::1 -M do -c1 -W2 -s 1300 fd00:3::2' >"$TMP/ptb6b" 2>&1 || true
cat "$TMP/ptb6a" "$TMP/ptb6b"
grep -qE 'mtu[ =]1400|mtu: 1400' "$TMP/ptb6a" || { echo "FAIL: no IPv6 PTB 1400" >&2; exit 1; }
grep -qE 'mtu[ =]1300|mtu: 1300' "$TMP/ptb6b" || { echo "FAIL: no IPv6 PTB 1300" >&2; exit 1; }
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -6 -I fd00:1::1 -M do -c2 -W2 -s 1252 fd00:3::2'
echo '--- IPv6 PTB blackhole / recovery ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec r2 ip6tables -I OUTPUT -p icmpv6 --icmpv6-type packet-too-big -j DROP; ip netns exec a ip -6 route flush cache; ip netns exec a ping -6 -I fd00:1::1 -M do -c2 -W2 -s 1300 fd00:3::2' >"$TMP/bh6" 2>&1 || true
cat "$TMP/bh6"
grep -q 'packet loss' "$TMP/bh6" || { echo "FAIL: IPv6 blackhole produced no loss" >&2; exit 1; }
grep -qE 'mtu[ =]1300|mtu: 1300' "$TMP/bh6" && { echo "FAIL: IPv6 blackhole still returned 1300 PTB" >&2; exit 1; }
ssh -o BatchMode=yes "$HOST" 'ip netns exec r2 ip6tables -D OUTPUT -p icmpv6 --icmpv6-type packet-too-big -j DROP; ip netns exec a ip -6 route flush cache; ip netns exec a ping -6 -I fd00:1::1 -M do -c1 -W2 -s 1300 fd00:3::2' >"$TMP/rec6" 2>&1 || true
cat "$TMP/rec6"
grep -qE 'mtu[ =]1300|mtu: 1300' "$TMP/rec6" || { echo "FAIL: no IPv6 PTB after restore" >&2; exit 1; }
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -6 -I fd00:1::1 -M do -c2 -W2 -s 1252 fd00:3::2'
echo "OK: netns PMTUD lab works (path MTU, TUN, TCP, hop-by-hop, blackhole/recovery)."
