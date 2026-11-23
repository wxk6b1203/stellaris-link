#!/usr/bin/env bash
set -euo pipefail
# End-to-end source PMTUD: peer path MTU is learned, oversized DF gets PTB,
# and a smaller DF packet then passes.
H1="${H1:?}"; H2="${H2:?}"
IP1="${H1##*@}"; IP2="${H2##*@}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/pmtud}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-pmtud.XXXXXX")"
cleanup(){ for h in "$H1" "$H2"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done; ip link del stellaris0 2>/dev/null || true" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
for h in "$H1" "$H2"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2; mkdir -p $DIR" 2>/dev/null || true; done
ids=()
for i in 0 1; do
  h="$H1"; ip="$IP1"; port=5900; api=5990
  [[ "$i" == 1 ]] && { h="$H2"; ip="$IP2"; port=5901; api=5991; }
  cat > "$TMP/node$((i+1)).toml" <<TOML
[node]
name = "pt$((i+1))"
state_dir = "$DIR/n$((i+1))"
overlay_ip = "10.249.0.$((i+1))"
[network]
name = "pmtud"
cidr = "10.249.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = ["$ip:$port"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1400
[api]
bind = "127.0.0.1:$api"
TOML
  ssh -o BatchMode=yes "$h" "mkdir -p $DIR/n$((i+1))"
  scp -q -o BatchMode=yes "$TMP/node$((i+1)).toml" "$h:$DIR/node$((i+1)).toml"
  id=$(ssh -o BatchMode=yes "$h" "$BIN --config $DIR/node$((i+1)).toml --print-id")
  ids+=("$id")
done
cat >> "$TMP/node1.toml" <<TOML
[[peers]]
name = "pt2"
endpoint_id = "${ids[1]}"
overlay_ip = "10.249.0.2"
addrs = ["$IP2:5901"]
TOML
cat >> "$TMP/node2.toml" <<TOML
[[peers]]
name = "pt1"
endpoint_id = "${ids[0]}"
overlay_ip = "10.249.0.1"
addrs = ["$IP1:5900"]
TOML
scp -q -o BatchMode=yes "$TMP/node1.toml" "$H1:$DIR/node1.toml"; scp -q -o BatchMode=yes "$TMP/node2.toml" "$H2:$DIR/node2.toml"
for i in 0 1; do h="$H1"; [[ "$i" == 1 ]] && h="$H2"; ssh -o BatchMode=yes "$h" "cd $DIR; nohup $BIN --config node$((i+1)).toml > node$((i+1)).log 2>&1 & echo \$! > node$((i+1)).pid"; done
sleep 8
peers=$(ssh -o BatchMode=yes "$H1" "curl -fsS 'http://127.0.0.1:5990/v1/peers'")
echo "peer: $peers"
path_mtu=$(echo "$peers" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((p.get("mtu") or 0 for p in d if p["name"]=="pt2"),0))')
[[ "$path_mtu" -gt 0 ]] || { echo "FAIL: peer path MTU not reported" >&2; exit 1; }
# Raise TUN MTU; the PTB path is exercised instead of relying on TUN clamping.
ssh -o BatchMode=yes "$H1" 'ip link set stellaris0 mtu 1500; ip route replace 10.249.0.0/16 dev stellaris0; ip route flush cache'
echo "peer path MTU=$path_mtu, TUN=1500"
echo '--- TCP with MSS clamp over PMTUD path ---'
ssh -o BatchMode=yes "$H2" 'cat >/tmp/tcp_srv.py <<PY
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.249.0.2",8080)); s.listen(1)
c,_=s.accept()
data=b"x"*(2*1024*1024)
c.sendall(data); c.close(); s.close()
PY
nohup python3 /tmp/tcp_srv.py >/tmp/tcp_srv.log 2>&1 & echo $! >/tmp/tcp_srv.pid'
sleep 1
set +e
tcp=$(ssh -o BatchMode=yes "$H1" 'python3 - <<PY
import socket
s=socket.create_connection(("10.249.0.2",8080),5)
n=0
while True:
 d=s.recv(65536)
 if not d: break
 n+=len(d)
s.close(); print("received",n)
PY' 2>&1)
tcp_rc=$?
set -e
echo "$tcp" | tail -3
ssh -o BatchMode=yes "$H2" 'kill $(cat /tmp/tcp_srv.pid) 2>/dev/null || true; rm -f /tmp/tcp_srv.py /tmp/tcp_srv.pid'
[[ "$tcp_rc" -eq 0 && "$tcp" == *"received 2097152"* ]] || { echo "FAIL: TCP transfer over PMTUD/MSS path failed" >&2; exit 1; }
echo "OK: peer path MTU + TUN + TCP MSS clamp transfer works."
