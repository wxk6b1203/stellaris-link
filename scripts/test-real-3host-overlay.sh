#!/usr/bin/env bash
set -euo pipefail
# Physical 3-host TUN overlay over the private VPC network.
# Required: H1 H2 H3 public SSH; P1 P2 P3 private IPs.
# Optional: BIN (default /opt/stellaris/stellaris-agent), DIR (default /opt/stellaris/overlay)
H1="${H1:?}"; H2="${H2:?}"; H3="${H3:?}"
P1="${P1:?}"; P2="${P2:?}"; P3="${P3:?}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/overlay}"
hosts=("$H1" "$H2" "$H3")
pips=("$P1" "$P2" "$P3")
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-real-overlay.XXXXXX")"
cleanup(){ for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done; ip link del stellaris0 2>/dev/null || true" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
ids=()
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2 $DIR/n3" 2>/dev/null || true; done
for i in 0 1 2; do
  p="${pips[$i]}"
  ip="10.251.0.$((i+1))"
  port=$((47001+i))
  api=$((48001+i))
  cat > "$TMP/node$((i+1)).toml" <<TOML
[node]
name = "host$((i+1))"
state_dir = "$DIR/n$((i+1))"
overlay_ip = "$ip"
[network]
name = "physical-overlay"
cidr = "10.251.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = $port
bind_ip = "$p"
advertise = ["$p:$port"]
[routing]
link_state = true
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1400
[api]
bind = "127.0.0.1:$api"
TOML
  ssh -o BatchMode=yes "${hosts[$i]}" "mkdir -p $DIR/n$((i+1))"
  scp -q -o BatchMode=yes "$TMP/node$((i+1)).toml" "${hosts[$i]}:$DIR/node$((i+1)).toml"
  id=$(ssh -o BatchMode=yes "${hosts[$i]}" "$BIN --config $DIR/node$((i+1)).toml --print-id")
  ids+=("$id")
done
for i in 0 1 2; do
  cat >> "$TMP/node$((i+1)).toml" <<TOML
TOML
  for j in 0 1 2; do
    [[ "$i" == "$j" ]] && continue
    cat >> "$TMP/node$((i+1)).toml" <<TOML
[[peers]]
name = "host$((j+1))"
endpoint_id = "${ids[$j]}"
overlay_ip = "10.251.0.$((j+1))"
addrs = ["${pips[$j]}:$((47001+j))"]
TOML
  done
  scp -q -o BatchMode=yes "$TMP/node$((i+1)).toml" "${hosts[$i]}:$DIR/node$((i+1)).toml"
  ssh -o BatchMode=yes "${hosts[$i]}" "cd $DIR; nohup $BIN --config node$((i+1)).toml > node$((i+1)).log 2>&1 & echo \$! > node$((i+1)).pid"
done
sleep 8
for i in 0 1 2; do
  echo "== host$((i+1)) peers =="
  ssh -o BatchMode=yes "${hosts[$i]}" "curl -fsS 'http://127.0.0.1:$((48001+i))/v1/peers'" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([(p["name"],p["connected"],p.get("path"),p.get("mtu")) for p in d])' 2>/dev/null || true
  ssh -o BatchMode=yes "${hosts[$i]}" "ip -4 addr show stellaris0; ip route" | tail -3
done
echo '--- IPv4 overlay ping ---'
ssh -o BatchMode=yes "$H1" 'ping -4 -c 3 -W 2 10.251.0.2'
ssh -o BatchMode=yes "$H2" 'ping -4 -c 3 -W 2 10.251.0.3'
ssh -o BatchMode=yes "$H1" 'ping -4 -c 3 -W 2 10.251.0.3'
echo '--- 1000-byte IPv4 ping ---'
ssh -o BatchMode=yes "$H1" 'ping -4 -c 3 -W 2 -s 1000 10.251.0.3'
echo '--- 2000-byte IPv4 ping (fragments) ---'
ssh -o BatchMode=yes "$H1" 'ping -4 -c 3 -W 2 -M dont -s 2000 10.251.0.3'
echo '--- logs ---'
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "tail -20 $DIR/node*.log" 2>/dev/null || true; done
ssh -o BatchMode=yes "$H1" 'ping -4 -c 2 -W 2 10.251.0.3 >/dev/null' && echo "OK: physical 3-host overlay IPv4 + fragmented ping works." 
