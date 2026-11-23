#!/usr/bin/env bash
set -euo pipefail
# Physical 3-host controller HA over private VPC addresses + Raft mTLS.
# Required:
#   H1 H2 H3     public SSH targets (root@...)
#   P1 P2 P3     private IPs used for Raft/member HTTP
# Optional:
#   BIN          remote controller path (default /opt/stellaris/stellaris-controller)
#   DIR          remote state dir (default /opt/stellaris/ha)
H1="${H1:?set H1}"; H2="${H2:?set H2}"; H3="${H3:?set H3}"
P1="${P1:?set P1}"; P2="${P2:?set P2}"; P3="${P3:?set P3}"
BIN="${BIN:-/opt/stellaris/stellaris-controller}"
DIR="${DIR:-/opt/stellaris/ha}"
SECRET="controller-secret"
RAFT_SECRET="raft-secret"
NODE="0101010101010101010101010101010101010101010101010101010101010101"
hosts=("$H1" "$H2" "$H3")
pips=("$P1" "$P2" "$P3")
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-real-ha.XXXXXX")"
cleanup(){ for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "rm -rf $DIR/n1 $DIR/n2 $DIR/n3; mkdir -p $DIR/tls"; done
# Generate one CA/server/client cert on H1, copy to all hosts.
ssh -o BatchMode=yes "$H1" "cd $DIR/tls && \
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout ca-key.pem -out ca.pem -subj '/CN=Stellaris Physical CA' -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1 && \
  openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj '/CN=stellaris-controller' >/dev/null 2>&1 && \
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:$P1,IP:$P2,IP:$P3\n' > server.ext && \
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 2 -extfile server.ext -out server.pem >/dev/null 2>&1"
for f in ca.pem server.pem server-key.pem; do scp -q -o BatchMode=yes "$H1:$DIR/tls/$f" "$TMP/"; done
for h in "${hosts[@]:1}"; do ssh -o BatchMode=yes "$h" "mkdir -p $DIR/tls"; scp -q -o BatchMode=yes "$TMP"/{ca.pem,server.pem,server-key.pem} "$h:$DIR/tls/"; done
for i in 0 1 2; do
  p="${pips[$i]}"
  boot=false; [[ "$i" == 0 ]] && boot=true
  cat > "$TMP/ctrl$((i+1)).toml" <<TOML
[node]
name = "c$((i+1))"
role = "controller"
state_dir = "$DIR/n$((i+1))/state"
overlay_ip = "10.250.0.$((i+1))"
[network]
name = "physical-ha"
cidr = "10.250.0.0/16"
[control]
bind = "$p:7801"
secret = "$SECRET"
raft_dir = "$DIR/n$((i+1))/raft"
raft_id = $((i+1))
raft_bind = "$p:7901"
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
addr = "$P1:7901"
[[control.raft_peers]]
id = 2
addr = "$P2:7901"
[[control.raft_peers]]
id = 3
addr = "$P3:7901"
[[control.join_tokens]]
token = "join-physical"
prefixes = ["192.168.250.0/24"]
TOML
  scp -q -o BatchMode=yes "$TMP/ctrl$((i+1)).toml" "${hosts[$i]}:$DIR/ctrl$((i+1)).toml"
  ssh -o BatchMode=yes "${hosts[$i]}" "mkdir -p $DIR/n$((i+1))/state $DIR/n$((i+1))/raft; cd $DIR; nohup $BIN --config ctrl$((i+1)).toml > ctrl$((i+1)).log 2>&1 & echo \$! > ctrl$((i+1)).pid"
done
status(){ ssh -o BatchMode=yes "$H1" "curl -fsS --max-time 3 -H 'x-stellaris-secret: $SECRET' 'http://$1:7801/v1/status'"; }
for _ in $(seq 1 120); do
  for i in 1 2 3; do
    if status "${pips[$((i-1))]}" >/dev/null 2>&1; then
      L=$(status "${pips[$((i-1))]}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      [[ -n "$L" ]] && break 2
    fi
  done
  sleep 0.25
done
[[ -n "${L:-}" ]] || { echo "FAIL: no leader" >&2; for h in "${hosts[@]}"; do ssh "$h" "tail -40 $DIR/ctrl*.log" 2>/dev/null || true; done; exit 1; }
echo "physical leader=$L"
JOIN=$(python3 - <<'PY'
import json
print(json.dumps({"node_id":"0101010101010101010101010101010101010101010101010101010101010101","overlay_ip":"10.250.0.10","token":"join-physical"}))
PY
)
ssh -o BatchMode=yes "$H1" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$JOIN' 'http://${pips[$((L-1))]}:7801/v1/join'" >/dev/null
LSA=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.250.0/24","metric":0}],"overlay_ip":"10.250.0.10","addrs":[]}))
PY
)
ssh -o BatchMode=yes "$H1" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$LSA' 'http://${pips[$((L-1))]}:7801/v1/lsa'" >/dev/null
sleep 1
ssh -o BatchMode=yes "$H1" "curl -fsS -H 'x-stellaris-secret: $SECRET' 'http://${pips[$((L-1))]}:7801/v1/snapshot?node=$NODE'" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("physical snapshot ok")'
ssh -o BatchMode=yes "${hosts[$((L-1))]}" "kill -9 \$(cat $DIR/ctrl$L.pid)"
for _ in $(seq 1 160); do
  for i in 1 2 3; do
    [[ "$i" == "$L" ]] && continue
    if status "${pips[$((i-1))]}" >/dev/null 2>&1; then
      NL=$(status "${pips[$((i-1))]}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      [[ -n "$NL" && "$NL" != "$L" ]] && break 2
    fi
  done
  sleep 0.25
done
[[ -n "${NL:-}" ]] || { echo "FAIL: no new leader" >&2; exit 1; }
echo "physical new leader=$NL"
LSA2=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":2,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.250.0/24","metric":0}],"overlay_ip":"10.250.0.10","addrs":[]}))
PY
)
ssh -o BatchMode=yes "$H1" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$LSA2' 'http://${pips[$((NL-1))]}:7801/v1/lsa'" >/dev/null
sleep 1
ssh -o BatchMode=yes "$H1" "curl -fsS -H 'x-stellaris-secret: $SECRET' 'http://${pips[$((NL-1))]}:7801/v1/snapshot?node=$NODE'" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("physical failover snapshot ok")'
echo "OK: physical 3-host controller HA + mTLS + failover works."
