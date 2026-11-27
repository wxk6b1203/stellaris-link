#!/usr/bin/env bash
set -euo pipefail
# Cross-region controller quorum over public TCP ports 5689-6000.
H1="${H1:?}"; H2="${H2:?}"; H3="${H3:?}"
IP1="${H1##*@}"; IP2="${H2##*@}"; IP3="${H3##*@}"
BIN="${BIN:-/opt/stellaris/stellaris-controller}"
DIR="${DIR:-/opt/stellaris/xha}"
SECRET="controller-secret"; RAFT_SECRET="raft-secret"
NODE="0101010101010101010101010101010101010101010101010101010101010101"
C_PORT=5801; R_PORT=5701
hosts=("$H1" "$H2" "$H3"); ips=("$IP1" "$IP2" "$IP3")
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-xha.XXXXXX")"
cleanup(){ for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2 $DIR/n3; mkdir -p $DIR/tls"; done
ssh -o BatchMode=yes "$H1" "cd $DIR/tls && \
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout ca-key.pem -out ca.pem -subj '/CN=Stellaris XB CA' -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1 && \
  openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj '/CN=stellaris-controller' >/dev/null 2>&1 && \
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:$IP1,IP:$IP2,IP:$IP3\n' > server.ext && \
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 2 -extfile server.ext -out server.pem >/dev/null 2>&1"
for f in ca.pem server.pem server-key.pem; do scp -q -o BatchMode=yes "$H1:$DIR/tls/$f" "$TMP/"; done
for h in "${hosts[@]:1}"; do scp -q -o BatchMode=yes "$TMP"/{ca.pem,server.pem,server-key.pem} "$h:$DIR/tls/"; done
for i in 0 1 2; do
  boot=false; [[ "$i" == 0 ]] && boot=true
  cat > "$TMP/ctrl$((i+1)).toml" <<TOML
[node]
name = "xc$((i+1))"
role = "controller"
state_dir = "$DIR/n$((i+1))/state"
overlay_ip = "10.248.0.$((i+1))"
[network]
name = "crossbatch-ha"
cidr = "10.248.0.0/16"
[control]
bind = "0.0.0.0:$C_PORT"
secret = "$SECRET"
allow_unsigned_lsa = true
raft_dir = "$DIR/n$((i+1))/raft"
raft_id = $((i+1))
raft_bind = "0.0.0.0:$R_PORT"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $boot
raft_tls_cert = "$DIR/tls/server.pem"
raft_tls_key = "$DIR/tls/server-key.pem"
raft_tls_ca = "$DIR/tls/ca.pem"
raft_tls_client_cert = "$DIR/tls/server.pem"
raft_tls_client_key = "$DIR/tls/server-key.pem"
raft_tls_require_client_cert = true
[[control.raft_peers]]
id = 1
addr = "$IP1:$R_PORT"
[[control.raft_peers]]
id = 2
addr = "$IP2:$R_PORT"
[[control.raft_peers]]
id = 3
addr = "$IP3:$R_PORT"
[[control.members]]
node_id = "0101010101010101010101010101010101010101010101010101010101010101"
overlay_ip = "10.248.0.10"
prefixes = ["192.168.250.0/24"]
TOML
  scp -q -o BatchMode=yes "$TMP/ctrl$((i+1)).toml" "${hosts[$i]}:$DIR/ctrl$((i+1)).toml"
  ssh -o BatchMode=yes "${hosts[$i]}" "mkdir -p $DIR/n$((i+1))/state $DIR/n$((i+1))/raft; cd $DIR; nohup $BIN --config ctrl$((i+1)).toml > ctrl$((i+1)).log 2>&1 & echo \$! > ctrl$((i+1)).pid"
done
status(){ ssh -o BatchMode=yes "${hosts[$1]}" "curl -fsS --max-time 3 -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/status'"; }
L=""; for _ in $(seq 1 120); do
  for i in 0 1 2; do
    if status "$i" >/dev/null 2>&1; then
      L=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      [[ -n "$L" ]] && break 2
    fi
  done
  sleep 0.5
done
[[ -n "$L" ]] || { echo "FAIL: no leader" >&2; for h in "${hosts[@]}"; do ssh "$h" "tail -30 $DIR/ctrl*.log" 2>/dev/null; done; exit 1; }
LI=$((L-1)); echo "cross-region leader=$L"
LSA=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.250.0/24","metric":0}],"overlay_ip":"10.248.0.10","addrs":[]}))
PY
)
ssh -o BatchMode=yes "${hosts[$LI]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$LSA' 'http://127.0.0.1:$C_PORT/v1/lsa'" >/dev/null
ssh -o BatchMode=yes "${hosts[$LI]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/snapshot?node=$NODE'" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]); print("cross-region snapshot ok")'
ssh -o BatchMode=yes "${hosts[$LI]}" "kill -9 \$(cat $DIR/ctrl$L.pid)"
NL=""; for _ in $(seq 1 160); do
  for i in 0 1 2; do
    [[ "$((i+1))" == "$L" ]] && continue
    if status "$i" >/dev/null 2>&1; then
      NL=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      [[ -n "$NL" && "$NL" != "$L" ]] && break 2
    fi
  done
  sleep 0.5
done
[[ -n "$NL" ]] || { echo "FAIL: no new leader" >&2; exit 1; }
echo "cross-region new leader=$NL"
LSA2=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":2,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.250.0/24","metric":0}],"overlay_ip":"10.248.0.10","addrs":[]}))
PY
)
ssh -o BatchMode=yes "${hosts[$((NL-1))]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$LSA2' 'http://127.0.0.1:$C_PORT/v1/lsa'" >/dev/null
sleep 1
ssh -o BatchMode=yes "${hosts[$((NL-1))]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/snapshot?node=$NODE'" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]); print("cross-region failover snapshot ok")'
echo "OK: cross-region controller quorum + mTLS + failover with a pre-registered member works."
