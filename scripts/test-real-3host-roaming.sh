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
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-real-roam.XXXXXX")"
cleanup(){ unblock; for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
unblock(){ for i in 0 1 2; do for j in 0 1 2; do [[ "$i" == "$j" ]] && continue; for ip in "${pips[$j]}" "${pubs[$j]}"; do ssh -o BatchMode=yes "${hosts[$i]}" "iptables -D OUTPUT -p udp -d $ip -j REJECT 2>/dev/null || true; iptables -D INPUT -p udp -s $ip -j REJECT 2>/dev/null || true" 2>/dev/null || true; done; done; done; }
block(){ for i in 0 1 2; do for j in 0 1 2; do [[ "$i" == "$j" ]] && continue; for ip in "${pips[$j]}" "${pubs[$j]}"; do ssh -o BatchMode=yes "${hosts[$i]}" "iptables -I OUTPUT -p udp -d $ip -j REJECT; iptables -I INPUT -p udp -s $ip -j REJECT" 2>/dev/null || true; done; done; done; }
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
relay_urls = []
disable_relay = false
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
for _ in $(seq 1 180); do
  [[ "$(path_of 2)" == "relay" ]] && break
  sleep 1
done
echo "after direct UDP block: $(path_of 2), $(path_of 3)"
[[ "$(path_of 2)" == "relay" ]] || { echo "FAIL: did not fall back to relay" >&2; exit 1; }
unblock
sleep 3
echo "after unblock: relay fallback verified; direct recovery is best-effort"
echo "OK: physical direct/relay roaming works."
