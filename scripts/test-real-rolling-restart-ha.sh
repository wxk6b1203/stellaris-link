#!/usr/bin/env bash
set -euo pipefail
# Shenzhen / Shanghai / Chengdu real 3-controller rolling restart over public TCP.
H1="${H1:?}"; H2="${H2:?}"; H3="${H3:?}"
IP1="${H1##*@}"; IP2="${H2##*@}"; IP3="${H3##*@}"
BIN="${BIN:-/opt/stellaris/stellaris-controller}"
DIR="${DIR:-/opt/stellaris/rolling-ha}"
SECRET="controller-secret"; RAFT_SECRET="raft-secret"
# Written into each controller TOML as control.raft_election_timeout_ms, which
# defaults to the cross-region value (1000 ms) when omitted.
ELECTION_MS="${ELECTION_MS:-1000}"
NODE="0101010101010101010101010101010101010101010101010101010101010101"
C_PORT=5801; R_PORT=5701
hosts=("$H1" "$H2" "$H3"); ips=("$IP1" "$IP2" "$IP3")
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-rolling-ha.XXXXXX")"
cleanup(){ for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill \$(cat \"\$f\") 2>/dev/null || true; done; pkill -9 -f '[c]trl[1-3].toml' 2>/dev/null || true" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
for h in "${hosts[@]}"; do ssh -o BatchMode=yes "$h" "pkill -9 -f '[s]tellaris-controller --config $DIR/ctrl' 2>/dev/null || true; rm -rf $DIR; mkdir -p $DIR/tls"; done
ssh -o BatchMode=yes "$H1" "cd $DIR/tls && \
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout ca-key.pem -out ca.pem -subj '/CN=Stellaris Rolling CA' -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1 && \
  openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj '/CN=stellaris-controller' >/dev/null 2>&1 && \
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:$IP1,IP:$IP2,IP:$IP3\n' > server.ext && \
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 2 -extfile server.ext -out server.pem >/dev/null 2>&1"
for f in ca.pem server.pem server-key.pem; do scp -q -o BatchMode=yes "$H1:$DIR/tls/$f" "$TMP/"; done
for h in "${hosts[@]:1}"; do scp -q -o BatchMode=yes "$TMP"/{ca.pem,server.pem,server-key.pem} "$h:$DIR/tls/"; done
for i in 0 1 2; do
  boot=false; [[ "$i" == 0 ]] && boot=true
  cat > "$TMP/ctrl$((i+1)).toml" <<TOML
[node]
name = "rc$((i+1))"
role = "controller"
state_dir = "$DIR/n$((i+1))/state"
overlay_ip = "10.247.0.$((i+1))"
[network]
name = "rolling-ha"
cidr = "10.247.0.0/16"
[control]
bind = "0.0.0.0:$C_PORT"
secret = "$SECRET"
allow_unsigned_lsa = true
raft_dir = "$DIR/n$((i+1))/raft"
raft_id = $((i+1))
raft_bind = "0.0.0.0:$R_PORT"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $boot
raft_election_timeout_ms = $ELECTION_MS
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
overlay_ip = "10.247.0.10"
prefixes = ["192.168.251.0/24"]
TOML
  scp -q -o BatchMode=yes "$TMP/ctrl$((i+1)).toml" "${hosts[$i]}:$DIR/ctrl$((i+1)).toml"
  ssh -o BatchMode=yes "${hosts[$i]}" "mkdir -p $DIR/n$((i+1))/state $DIR/n$((i+1))/raft; cd $DIR; nohup $BIN --config ctrl$((i+1)).toml > ctrl$((i+1)).log 2>&1 & echo \$! > ctrl$((i+1)).pid"
done
status(){ ssh -o BatchMode=yes "${hosts[$1]}" "curl -fsS --max-time 3 -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/status'"; }
start_node(){ local i=$1; ssh -o BatchMode=yes "${hosts[$i]}" "cd $DIR; nohup $BIN --config ctrl$((i+1)).toml > ctrl$((i+1)).log 2>&1 & echo \$! > ctrl$((i+1)).pid"; }
find_leader(){ L=""; for _ in $(seq 1 120); do for i in 0 1 2; do if status "$i" >/dev/null 2>&1; then L=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")'); [[ -n "$L" ]] && return 0; fi; done; sleep 0.5; done; return 1; }
snapshot_ok(){ local i=$1; ssh -o BatchMode=yes "${hosts[$i]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/snapshot?node=$NODE'" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("snapshot members ok")'; }
wait_all(){ for _ in $(seq 1 120); do local ok=1; for j in 0 1 2; do status "$j" >/dev/null 2>&1 || ok=0; done; [[ "$ok" == 1 ]] && return 0; sleep 0.5; done; return 1; }
snapshot_retry(){ local i=$1; for _ in $(seq 1 60); do snapshot_ok "$i" && return 0; sleep 0.5; done; return 1; }
LSA1='{"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":null,"links":[],"prefixes":[{"prefix":"192.168.251.0/24","metric":0}],"overlay_ip":"10.247.0.10","addrs":[]}'
find_leader || { echo "FAIL: no initial leader" >&2; exit 1; }
echo "initial leader=$L"
TIMING=$(status "$((L-1))" | python3 -c 'import json,sys; r=(json.load(sys.stdin).get("raft") or {}); print(r.get("election_timeout_min_ms"), r.get("source"))')
[[ "$TIMING" == "$ELECTION_MS config" ]] || {
  echo "FAIL: raft timing '$TIMING', want '$ELECTION_MS config'" >&2; exit 1; }
for i in 0 1 2; do
  ssh -o BatchMode=yes "${hosts[$i]}" "grep -q 'raft election timing' $DIR/ctrl$((i+1)).log" || {
    echo "FAIL: ctrl$((i+1)) did not log raft timing" >&2; exit 1; }
done
echo "raft timing ok: ${TIMING%% *}ms source=${TIMING##* }"
ssh -o BatchMode=yes "${hosts[$((L-1))]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$LSA1' 'http://127.0.0.1:$C_PORT/v1/lsa'" >/dev/null
snapshot_ok "$((L-1))"
# Rolling restart followers first.
for i in 0 1 2; do
  [[ "$((i+1))" == "$L" ]] && continue
  echo "--- restart follower $((i+1)) ---"
  ssh -o BatchMode=yes "${hosts[$i]}" "kill -9 \$(cat $DIR/ctrl$((i+1)).pid)"
  sleep 1
  start_node "$i"
  wait_all
  find_leader || { echo "FAIL: no leader after follower $((i+1))" >&2; exit 1; }
  echo "leader after follower $((i+1))=$L"
  snapshot_retry "$((L-1))"
done
# Restart the current leader last.
find_leader || { echo "FAIL: no current leader" >&2; exit 1; }
OLD=$L
echo "--- restart leader $OLD ---"
ssh -o BatchMode=yes "${hosts[$((OLD-1))]}" "kill -9 \$(cat $DIR/ctrl$OLD.pid)"
NL=""; for _ in $(seq 1 160); do
  for i in 0 1 2; do
    [[ "$((i+1))" == "$OLD" ]] && continue
    if status "$i" >/dev/null 2>&1; then
      NL=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      [[ -n "$NL" && "$NL" != "$OLD" ]] && break 2
    fi
  done
  sleep 0.5
done
[[ -n "$NL" ]] || { echo "FAIL: no new leader" >&2; exit 1; }
echo "new leader=$NL"
LSA2='{"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":2,"zone":null,"links":[],"prefixes":[{"prefix":"192.168.251.0/24","metric":0}],"overlay_ip":"10.247.0.10","addrs":[]}'
ssh -o BatchMode=yes "${hosts[$((NL-1))]}" "curl -fsS -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$LSA2' 'http://127.0.0.1:$C_PORT/v1/lsa'" >/dev/null
start_node "$((OLD-1))"
wait_all
snapshot_retry "$((NL-1))"
echo "OK: cross-region 3-controller rolling restart with a pre-registered member works."
