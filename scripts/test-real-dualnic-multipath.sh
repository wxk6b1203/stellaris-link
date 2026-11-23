#!/usr/bin/env bash
set -euo pipefail
# Batch2: A 47.119.37.129 has two private NICs in the same /24.
# Force B's selected direct path to A from one IP to the other.
H1="${H1:?}"; H2="${H2:?}"; H3="${H3:?}"
P1="${P1:?}"; P1B="${P1B:?}"; P2="${P2:?}"; P3="${P3:?}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/multipath}"
hosts=("$H1" "$H2" "$H3")
pips=("$P1" "$P2" "$P3")
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-dualnic.XXXXXX")"
selected=""
cleanup(){ if [[ -n "$selected" ]]; then ssh -o BatchMode=yes "$H2" "iptables -D OUTPUT -p udp -d $selected -j REJECT 2>/dev/null || true; iptables -D INPUT -p udp -s $selected -j REJECT 2>/dev/null || true" 2>/dev/null || true; fi; ssh -o BatchMode=yes "$H1" "tc qdisc del dev eth1 root 2>/dev/null || true; tc qdisc del dev eth0 root 2>/dev/null || true; ip rule del from $P1B table 164 2>/dev/null || true; ip route flush table 164" 2>/dev/null || true; for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
ssh -o BatchMode=yes "$H1" "for f in all eth0 eth1; do sysctl -w net.ipv4.conf.\$f.arp_ignore=1 net.ipv4.conf.\$f.arp_announce=2 net.ipv4.conf.\$f.rp_filter=0 >/dev/null; done; ip rule add from $P1B table 164 2>/dev/null || true; ip route replace 192.168.0.0/24 dev eth1 table 164; ip route replace default via 192.168.0.253 dev eth1 table 164" 2>/dev/null || true
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2 $DIR/n3; mkdir -p $DIR" 2>/dev/null || true; done
ids=()
for i in 0 1 2; do
  p="${pips[$i]}"; ip="10.254.0.$((i+1))"; port=$((5911+i)); api=$((5981+i))
  addrs="\"$p:$port\""
  [[ "$i" == 0 ]] && addrs="\"$P1:$port\", \"$P1B:$port\""
  cat > "$TMP/node$((i+1)).toml" <<TOML
[node]
name = "mp$((i+1))"
state_dir = "$DIR/n$((i+1))"
overlay_ip = "$ip"
[network]
name = "dualnic-multipath"
cidr = "10.254.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = [$addrs]
[routing]
link_state = true
[dataplane]
enabled = false
[api]
bind = "127.0.0.1:$api"
TOML
  ssh -o BatchMode=yes "${hosts[$i]}" "mkdir -p $DIR/n$((i+1))"
  scp -q -o BatchMode=yes "$TMP/node$((i+1)).toml" "${hosts[$i]}:$DIR/node$((i+1)).toml"
  id=$(ssh -o BatchMode=yes "${hosts[$i]}" "$BIN --config $DIR/node$((i+1)).toml --print-id")
  ids+=("$id")
done
for i in 0 1 2; do
  for j in 0 1 2; do
    [[ "$i" == "$j" ]] && continue
    peer_addrs="\"${pips[$j]}:$((5911+j))\""
    if [[ "$i" != 0 && "$j" == 0 ]]; then
      peer_addrs="\"$P1:5911\", \"$P1B:5911\""
    fi
    cat >> "$TMP/node$((i+1)).toml" <<TOML
[[peers]]
name = "mp$((j+1))"
endpoint_id = "${ids[$j]}"
overlay_ip = "10.254.0.$((j+1))"
addrs = [$peer_addrs]
TOML
  done
  # A needs both of its own IPs as peer addrs from B/C; add for B/C below.
  scp -q -o BatchMode=yes "$TMP/node$((i+1)).toml" "${hosts[$i]}:$DIR/node$((i+1)).toml"
  ssh -o BatchMode=yes "${hosts[$i]}" "cd $DIR; nohup $BIN --config node$((i+1)).toml > node$((i+1)).log 2>&1 & echo \$! > node$((i+1)).pid"
done
sleep 7
peers_b(){ ssh -o BatchMode=yes "$H2" "curl -fsS 'http://127.0.0.1:5982/v1/peers'"; }
path_addr(){ peers_b | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p.get('path_addr') or '' for p in d if p['name']=='mp1'), ''))" 2>/dev/null; }
path_count(){ peers_b | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p.get('path_count') or 0 for p in d if p['name']=='mp1'), 0))" 2>/dev/null; }
initial="$(path_addr)"
echo "B -> A selected path_addr: $initial path_count=$(path_count)"
[[ -n "$initial" ]] || { echo "FAIL: no selected path_addr" >&2; exit 1; }
selected="${initial%:*}"
other="$P1B"; [[ "$selected" == "$P1B" ]] && other="$P1"
if [[ "$selected" == "$P1B" ]]; then
  echo '--- RTT-based path selection (delay .164 by 100ms) ---'
  ssh -o BatchMode=yes "$H1" 'tc qdisc add dev eth1 root netem delay 100ms'
  sleep 12
  echo "after delay: $(path_addr) path_count=$(path_count)"
  ssh -o BatchMode=yes "$H1" 'tc qdisc del dev eth1 root'
  sleep 2
  echo '--- loss-based path selection (20% loss on .164) ---'
  ssh -o BatchMode=yes "$H1" 'tc qdisc add dev eth1 root netem loss 20%'
  sleep 12
  echo "after loss: $(path_addr) path_count=$(path_count)"
  ssh -o BatchMode=yes "$H1" 'tc qdisc del dev eth1 root'
  sleep 2
else
  echo "SKIP RTT/loss selection: selected path is $selected, not .164"
fi
ssh -o BatchMode=yes "$H2" "iptables -I OUTPUT -p udp -d $selected -j REJECT; iptables -I INPUT -p udp -s $selected -j REJECT"
changed=""
for _ in $(seq 1 120); do
  changed="$(path_addr)"
  [[ -n "$changed" && "$changed" != "$initial" ]] && break
  sleep 1
done
echo "B -> A after blocking $selected: $changed"
if [[ -n "$changed" && "$changed" != "$initial" ]]; then
  echo "OK: dual-NIC direct path failover works."
else
  echo "FAIL: dual-NIC path did not change" >&2
  exit 1
fi
