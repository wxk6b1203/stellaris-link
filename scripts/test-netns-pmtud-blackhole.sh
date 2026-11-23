#!/usr/bin/env bash
set -euo pipefail
# Chengdu netns: real agent traffic through a PTB blackhole, then recovery.
HOST="${HOST:-root@47.109.58.88}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR=/opt/stellaris/pmtud-bh
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-bh.XXXXXX")"
cleanup(){
  ssh -o BatchMode=yes "$HOST" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done; ip netns exec r2 iptables -D OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP 2>/dev/null || true; ip netns exec r2 ip link set r2b mtu 1300 2>/dev/null || true; ip netns exec b ip link set b0 mtu 1300 2>/dev/null || true; ip netns exec a ip link del stellaris0 2>/dev/null || true; ip netns exec b ip link del stellaris0 2>/dev/null || true; rm -rf $DIR" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
ssh -o BatchMode=yes "$HOST" "rm -rf $DIR; mkdir -p $DIR/a-state $DIR/b-state"
cat > "$TMP/a.toml" <<TOML
[node]
name="bh-a"
state_dir="$DIR/a-state"
overlay_ip="10.71.0.1"
[network]
name="ptb-blackhole"
cidr="10.71.0.0/16"
[transport]
relay_urls=[]
disable_relay=true
listen_port=5931
bind_ip="10.0.1.1"
advertise=["10.0.1.1:5931"]
[routing]
link_state=true
[dataplane]
enabled=true
tun_name="stellaris0"
mtu=1400
[api]
bind="127.0.0.1:5983"
TOML
cat > "$TMP/b.toml" <<TOML
[node]
name="bh-b"
state_dir="$DIR/b-state"
overlay_ip="10.71.0.2"
[network]
name="ptb-blackhole"
cidr="10.71.0.0/16"
[transport]
relay_urls=[]
disable_relay=true
listen_port=5932
bind_ip="10.0.3.2"
advertise=["10.0.3.2:5932"]
[routing]
link_state=true
[dataplane]
enabled=true
tun_name="stellaris0"
mtu=1400
[api]
bind="127.0.0.1:5984"
TOML
A_ID=$(ssh -o BatchMode=yes "$HOST" "ip netns exec a $BIN --config /dev/stdin --print-id" < "$TMP/a.toml")
B_ID=$(ssh -o BatchMode=yes "$HOST" "ip netns exec b $BIN --config /dev/stdin --print-id" < "$TMP/b.toml")
cat >> "$TMP/a.toml" <<TOML
[[peers]]
name="bh-b"
endpoint_id="$B_ID"
overlay_ip="10.71.0.2"
addrs=["10.0.3.2:5932"]
TOML
cat >> "$TMP/b.toml" <<TOML
[[peers]]
name="bh-a"
endpoint_id="$A_ID"
overlay_ip="10.71.0.1"
addrs=["10.0.1.1:5931"]
TOML
scp -q "$TMP/a.toml" "$HOST:$DIR/a.toml"; scp -q "$TMP/b.toml" "$HOST:$DIR/b.toml"
ssh -o BatchMode=yes "$HOST" "ip netns exec a nohup $BIN --config $DIR/a.toml >$DIR/a.log 2>&1 & echo \$! >$DIR/a.pid; ip netns exec b nohup $BIN --config $DIR/b.toml >$DIR/b.log 2>&1 & echo \$! >$DIR/b.pid"
sleep 8
echo '--- baseline peers ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a curl -fsS http://127.0.0.1:5983/v1/peers; echo'
# server and long-lived client
cat > "$TMP/server.py" <<'PY'
import socket, time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.71.0.2",8081)); s.listen(1)
c,_=s.accept(); end=time.time()+75
while time.time()<end:
    try: c.sendall(b"x"*65536)
    except Exception: break
    time.sleep(0.03)
c.close(); s.close()
PY
cat > "$TMP/client.py" <<'PY'
import socket, time
s=socket.create_connection(("10.71.0.2",8081),5); s.settimeout(0.5)
start=last=time.time(); total=0; gaps=[]; last_print=start
while time.time()-start < 60:
    try:
        d=s.recv(65536)
        if not d: print("EOF", flush=True); break
        now=time.time(); total+=len(d)
        if now-last>1.5: gaps.append((round(last-start,1),round(now-start,1)))
        last=now
    except socket.timeout:
        pass
    if time.time()-last_print > 2:
        print("T", round(time.time()-start,1), "BYTES", total, flush=True)
        last_print=time.time()
print("TOTAL",total,"GAPS",gaps, flush=True)
s.close()
PY
scp -q "$TMP/server.py" "$HOST:$DIR/server.py"; scp -q "$TMP/client.py" "$HOST:$DIR/client.py"
ssh -o BatchMode=yes "$HOST" "ip netns exec b nohup python3 -m http.server 8082 --bind 10.71.0.2 >$DIR/http.log 2>&1 & echo \$! >$DIR/http.pid; ip netns exec b nohup python3 $DIR/server.py >$DIR/server.log 2>&1 & echo \$! >$DIR/server.pid; ip netns exec a nohup python3 $DIR/client.py >$DIR/client.log 2>&1 & echo \$! >$DIR/client.pid"
sleep 5
echo '--- baseline client log ---'; ssh -o BatchMode=yes "$HOST" "cat $DIR/client.log"
# lower MTU and blackhole PTB at r2
ssh -o BatchMode=yes "$HOST" 'ip netns exec r2 ip link set r2b mtu 1100; ip netns exec b ip link set b0 mtu 1100; ip netns exec r2 iptables -I OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP'
echo '--- blackhole applied (15s) ---'
sleep 15
ssh -o BatchMode=yes "$HOST" 'ip netns exec a curl -fsS http://127.0.0.1:5983/v1/peers; echo; ip netns exec a ip route get 10.71.0.2'
echo '--- restore MTU/PTB ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec r2 iptables -D OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP; ip netns exec r2 ip link set r2b mtu 1300; ip netns exec b ip link set b0 mtu 1300'
sleep 5
echo '--- new overlay HTTP flow after restore ---'
ssh -o BatchMode=yes "$HOST" 'ip netns exec a ping -c2 -W2 10.71.0.2 || true'
http_ok=0
ssh -o BatchMode=yes "$HOST" 'ip netns exec a curl -fsS --max-time 5 http://10.71.0.2:8082/ >/dev/null' && http_ok=1
echo "new_http_ok=$http_ok"
sleep 40
ssh -o BatchMode=yes "$HOST" 'ip netns exec a curl -fsS http://127.0.0.1:5983/v1/peers; echo'
sleep 10
ssh -o BatchMode=yes "$HOST" 'ip netns exec a curl -fsS http://127.0.0.1:5983/v1/peers; echo'
sleep 12
echo '--- client final ---'; ssh -o BatchMode=yes "$HOST" "cat $DIR/client.log"
echo '--- agent log tail ---'; ssh -o BatchMode=yes "$HOST" "tail -20 $DIR/a.log"
echo '--- server/client cleanup ---'
ssh -o BatchMode=yes "$HOST" 'kill $(cat /opt/stellaris/pmtud-bh/server.pid) $(cat /opt/stellaris/pmtud-bh/client.pid) 2>/dev/null || true'
echo "OK: blackhole test completed (inspect logs)."
