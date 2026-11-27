#!/usr/bin/env bash
set -euo pipefail
# Force direct UDP failure between physical hosts and verify relay fallback.
# Required: H1 H2 H3 public SSH; P1 P2 P3 private IPs.
H1="${H1:?}"; H2="${H2:?}"; H3="${H3:?}"
P1="${P1:?}"; P2="${P2:?}"; P3="${P3:?}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/roaming}"
hosts=("$H1" "$H2" "$H3")
pips=("$P1" "$P2" "$P3")
pubs=("${H1##*@}" "${H2##*@}" "${H3##*@}")
# iroh also probes IPv6; block each peer's global IPv6 addresses as well, but
# leave other IPv6 traffic (notably the N0 relay) reachable.
v6s=()
for h in "${hosts[@]}"; do
  v6s+=("$(ssh -o BatchMode=yes "$h" "ip -6 -o addr show scope global 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' '" 2>/dev/null || true)")
done
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-real-roam.XXXXXX")"
cleanup(){ unblock; for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
unblock(){ for i in 0 1 2; do for j in 0 1 2; do [[ "$i" == "$j" ]] && continue; for ip in "${pips[$j]}" "${pubs[$j]}"; do ssh -o BatchMode=yes "${hosts[$i]}" "iptables -D OUTPUT -p udp -d $ip -j REJECT 2>/dev/null || true; iptables -D INPUT -p udp -s $ip -j REJECT 2>/dev/null || true" 2>/dev/null || true; done; for v6 in ${v6s[$j]:-}; do ssh -o BatchMode=yes "${hosts[$i]}" "ip6tables -D OUTPUT -p udp -d $v6 -j REJECT 2>/dev/null || true; ip6tables -D INPUT -p udp -s $v6 -j REJECT 2>/dev/null || true" 2>/dev/null || true; done; done; done; }
block(){ for i in 0 1 2; do for j in 0 1 2; do [[ "$i" == "$j" ]] && continue; for ip in "${pips[$j]}" "${pubs[$j]}"; do ssh -o BatchMode=yes "${hosts[$i]}" "iptables -I OUTPUT -p udp -d $ip -j REJECT; iptables -I INPUT -p udp -s $ip -j REJECT" 2>/dev/null || true; done; for v6 in ${v6s[$j]:-}; do ssh -o BatchMode=yes "${hosts[$i]}" "ip6tables -I OUTPUT -p udp -d $v6 -j REJECT; ip6tables -I INPUT -p udp -s $v6 -j REJECT" 2>/dev/null || true; done; done; done; }
ids=()
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2 $DIR/n3" 2>/dev/null || true; done
for i in 0 1 2; do
  p="${pips[$i]}"; ip="10.252.0.$((i+1))"; port=$((47001+i)); api=$((48101+i))
  cat > "$TMP/node$((i+1)).toml" <<TOML
[node]
name = "roam$((i+1))"
state_dir = "$DIR/n$((i+1))"
overlay_ip = "$ip"
[network]
name = "physical-roaming"
cidr = "10.252.0.0/16"
[transport]
# Pin every endpoint to the same relay. With relay_mode=auto each host may
# register on a different N0 region (e.g. euc1 vs usw1), so a peer that only
# knows another region's relay URL cannot fall back there.
relay_mode = "custom"
relay_urls = ["https://usw1-1.relay.n0.iroh.link/"]
disable_relay = false
# Keep the peer set to the static IPv4 addresses below: iroh address discovery
# would otherwise publish IPv6 addresses and the direct path would survive an
# IPv4 iptables block, making the relay fallback assertion meaningless.
disable_discovery = true
listen_port = $port
bind_ip = "$p"
advertise = ["$p:$port"]
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
    cat >> "$TMP/node$((i+1)).toml" <<TOML
[[peers]]
name = "roam$((j+1))"
endpoint_id = "${ids[$j]}"
overlay_ip = "10.252.0.$((j+1))"
addrs = ["${pips[$j]}:$((47001+j))"]
relay_url = "https://usw1-1.relay.n0.iroh.link/"
TOML
  done
  scp -q -o BatchMode=yes "$TMP/node$((i+1)).toml" "${hosts[$i]}:$DIR/node$((i+1)).toml"
  ssh -o BatchMode=yes "${hosts[$i]}" "cd $DIR; nohup $BIN --config node$((i+1)).toml > node$((i+1)).log 2>&1 & echo \$! > node$((i+1)).pid"
done
peers_json(){ ssh -o BatchMode=yes "$H1" "curl -fsS 'http://127.0.0.1:48101/v1/peers'"; }
path_of(){ peers_json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p.get('path') or '' for p in d if p['name']=='roam$1'), ''))" 2>/dev/null; }
for _ in $(seq 1 120); do
  [[ "$(path_of 2)" == "direct" && "$(path_of 3)" == "direct" ]] && break
  sleep 0.5
done
echo "initial paths: $(path_of 2), $(path_of 3)"
[[ "$(path_of 2)" == "direct" ]] || { echo "FAIL: initial path is not direct" >&2; exit 1; }
block
p2=""; p3=""
for _ in $(seq 1 180); do
  p2="$(path_of 2)"; p3="$(path_of 3)"
  [[ "$p2" == "relay" && "$p3" == "relay" ]] && break
  sleep 1
done
echo "after direct UDP block: $p2, $p3"
[[ "$p2" == "relay" && "$p3" == "relay" ]] || {
  echo "FAIL: not all blocked paths fell back to relay" >&2; exit 1; }
unblock
sleep 3
echo "after unblock: relay fallback verified; direct recovery is best-effort"
echo "OK: physical direct/relay roaming works."
