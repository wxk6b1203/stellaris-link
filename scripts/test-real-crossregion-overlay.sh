#!/usr/bin/env bash
set -euo pipefail
# Shenzhen <-> Shanghai TUN overlay over public UDP ports 5900/5901.
H1="${H1:?}"; H2="${H2:?}"
IP1="${H1##*@}"; IP2="${H2##*@}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/crossregion}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-crossregion.XXXXXX")"
cleanup(){ for h in "$H1" "$H2"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done; ip link del stellaris0 2>/dev/null || true" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
for h in "$H1" "$H2"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2; mkdir -p $DIR" 2>/dev/null || true; done
ids=()
for i in 0 1; do
  h="$H1"; ip="$IP1"; port=5900; api=5990
  [[ "$i" == 1 ]] && { h="$H2"; ip="$IP2"; port=5901; api=5991; }
  cat > "$TMP/node$((i+1)).toml" <<TOML
[node]
name = "cr$((i+1))"
state_dir = "$DIR/n$((i+1))"
overlay_ip = "10.249.0.$((i+1))"
[network]
name = "crossregion"
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
name = "cr2"
endpoint_id = "${ids[1]}"
overlay_ip = "10.249.0.2"
addrs = ["$IP2:5901"]
TOML
cat >> "$TMP/node2.toml" <<TOML
[[peers]]
name = "cr1"
endpoint_id = "${ids[0]}"
overlay_ip = "10.249.0.1"
addrs = ["$IP1:5900"]
TOML
scp -q -o BatchMode=yes "$TMP/node1.toml" "$H1:$DIR/node1.toml"; scp -q -o BatchMode=yes "$TMP/node2.toml" "$H2:$DIR/node2.toml"
for i in 0 1; do h="$H1"; [[ "$i" == 1 ]] && h="$H2"; ssh -o BatchMode=yes "$h" "cd $DIR; nohup $BIN --config node$((i+1)).toml > node$((i+1)).log 2>&1 & echo \$! > node$((i+1)).pid"; done
sleep 8
ssh -o BatchMode=yes "$H1" 'ip -4 addr show stellaris0; ip route | grep 10.256 || true'
echo '--- cross-region ping ---'
ssh -o BatchMode=yes "$H1" 'ping -4 -c 4 -W 3 10.249.0.2'
echo '--- 2000-byte fragmented ping ---'
ssh -o BatchMode=yes "$H1" 'ping -4 -c 4 -W 3 -M dont -s 2000 10.249.0.2'
echo '--- peers ---'
ssh -o BatchMode=yes "$H1" "curl -fsS 'http://127.0.0.1:5990/v1/peers'"
echo "OK: cross-region TUN overlay works."
