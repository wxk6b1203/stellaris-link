#!/usr/bin/env bash
set -euo pipefail
# Batch1 <-> Batch2 public relay connectivity. Batch private networks do not route.
H1="${H1:?}"; H2="${H2:?}"
BIN="${BIN:-/opt/stellaris/stellaris-agent}"
DIR="${DIR:-/opt/stellaris/crossbatch}"
RELAY="${RELAY:-https://usw1-1.relay.n0.iroh.link/}"
RELAY2="${RELAY2:-https://aps1-1.relay.n0.iroh.link/}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-crossbatch.XXXXXX")"
cleanup(){ for h in "$H1" "$H2"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
for h in "$H1" "$H2"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2; mkdir -p $DIR" 2>/dev/null || true; done
ids=()
for i in 0 1; do
  h="${H1}"; [[ "$i" == 1 ]] && h="${H2}"
  port=$((5900+i)); api=$((5990+i))
  cat > "$TMP/node$((i+1)).toml" <<TOML
[node]
name = "xb$((i+1))"
state_dir = "$DIR/n$((i+1))"
overlay_ip = "10.255.0.$((i+1))"
[network]
name = "crossbatch-relay"
cidr = "10.255.0.0/16"
[transport]
relay_urls = ["$RELAY", "$RELAY2"]
disable_relay = false
listen_port = $port
[routing]
link_state = true
[dataplane]
enabled = false
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
name = "xb2"
endpoint_id = "${ids[1]}"
overlay_ip = "10.255.0.2"
addrs = []
relay_url = "$RELAY"
TOML
cat >> "$TMP/node2.toml" <<TOML
[[peers]]
name = "xb1"
endpoint_id = "${ids[0]}"
overlay_ip = "10.255.0.1"
addrs = []
relay_url = "$RELAY"
TOML
scp -q -o BatchMode=yes "$TMP/node1.toml" "$H1:$DIR/node1.toml"; scp -q -o BatchMode=yes "$TMP/node2.toml" "$H2:$DIR/node2.toml"
for i in 0 1; do h="${H1}"; [[ "$i" == 1 ]] && h="${H2}"; ssh -o BatchMode=yes "$h" "cd $DIR; nohup $BIN --config node$((i+1)).toml > node$((i+1)).log 2>&1 & echo \$! > node$((i+1)).pid"; done
peers_json(){ ssh -o BatchMode=yes "$H1" "curl -fsS 'http://127.0.0.1:5990/v1/peers'" 2>/dev/null; }
path(){ peers_json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((p.get("path") or "" for p in d if p["name"]=="xb2"), ""))' 2>/dev/null; }
path_count(){ peers_json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((p.get("path_count") or 0 for p in d if p["name"]=="xb2"), 0))' 2>/dev/null; }
for _ in $(seq 1 90); do
  [[ "$(path)" == "relay" ]] && break
  sleep 1
done
p="$(path)"
echo "cross-batch path: $p path_count=$(path_count)"
[[ "$p" == "relay" ]] || { echo "FAIL: cross-batch relay path not established" >&2; exit 1; }
echo "OK: cross-batch public relay works."
