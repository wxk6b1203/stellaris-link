#!/usr/bin/env bash
# Real three-region controller HA under injected WAN loss and added RTT.
#
# Usage:
#   H1=root@<chengdu> H2=root@<shenzhen> H3=root@<shanghai> \
#     BIN=/opt/stellaris/stellaris-controller ./scripts/test-real-wan-loss-ha.sh
#
# Optional: ELECTION_MS (default 1000), LOSS (default 20%), DELAY (default 50ms).
# netem is applied only to egress towards the other two controller IPs, so the
# orchestrating SSH session keeps a clean path. Requires root and tc/u32.
set -u
H1="${H1:?}"; H2="${H2:?}"; H3="${H3:?}"
IP1="${H1##*@}"; IP2="${H2##*@}"; IP3="${H3##*@}"
BIN="${BIN:-/opt/stellaris/stellaris-controller}"
DIR="${DIR:-/opt/stellaris/wan-loss2}"
SECRET="controller-secret"; RAFT_SECRET="raft-secret"
ELECTION_MS="${ELECTION_MS:-1000}"
LOSS="${LOSS:-20%}"; DELAY="${DELAY:-50ms}"
C_PORT=5801; R_PORT=5701
NODE="0101010101010101010101010101010101010101010101010101010101010101"
hosts=("$H1" "$H2" "$H3"); ips=("$IP1" "$IP2" "$IP3")
TMP="$(mktemp -d /tmp/stellaris-wan2.XXXXXX)"
log(){ echo "[$(date +%H:%M:%S)] $*"; }
fail(){ log "FAIL: $*"; exit 1; }
sshx(){ ssh -o BatchMode=yes -o ConnectTimeout=6 "$@"; }
cleanup(){
  log "cleanup"
  for h in "${hosts[@]}"; do
    sshx "$h" "for f in $DIR/*.pid; do [ -f \"\$f\" ] && kill -9 \$(cat \"\$f\") 2>/dev/null; done; pkill -9 -f '[c]trl[1-3].toml' 2>/dev/null; tc qdisc del dev eth0 root >/dev/null 2>&1" >/dev/null 2>&1
  done
  rm -rf "$TMP"
}
trap cleanup EXIT
status_of(){ sshx "${hosts[$1]}" "curl -s --max-time 3 -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/status'" 2>/dev/null || true; }
leader_of(){ status_of "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null || true; }
snapshot_has_member(){
  sshx "${hosts[$1]}" "curl -fsS --max-time 10 -H 'x-stellaris-secret: $SECRET' 'http://127.0.0.1:$C_PORT/v1/snapshot?node=$NODE'" 2>/dev/null \
    | grep -q "$NODE"
}

for h in "${hosts[@]}"; do sshx "$h" "pkill -9 -f '[c]trl[1-3].toml' 2>/dev/null; rm -rf $DIR; mkdir -p $DIR; tc qdisc del dev eth0 root >/dev/null 2>&1" >/dev/null 2>&1; done
log "baseline ping from $IP1 to peers"
sshx "$H1" "ping -c 3 -q $IP2 2>/dev/null | tail -2; ping -c 3 -q $IP3 2>/dev/null | tail -2"
log "apply netem loss=$LOSS delay=$DELAY on egress to peer controllers"
for i in 0 1 2; do
  h="${hosts[$i]}"; a="${ips[$(((i+1)%3))]}"; b="${ips[$(((i+2)%3))]}"
  sshx "$h" "tc qdisc replace dev eth0 root handle 1: prio && tc qdisc replace dev eth0 parent 1:3 handle 30: netem delay $DELAY loss $LOSS && tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dst $a/32 flowid 1:3 && tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dst $b/32 flowid 1:3" || { log "FAIL: netem on $h"; exit 1; }
done
sshx "$H1" "ping -c 5 -q $IP2 2>/dev/null | tail -2"

for i in 0 1 2; do
  boot=false; [ "$i" = 0 ] && boot=true
  cat > "$TMP/ctrl$((i+1)).toml" <<TOML
[node]
name = "wc$((i+1))"
role = "controller"
state_dir = "$DIR/n$((i+1))/state"
overlay_ip = "10.248.0.$((i+1))"
[network]
name = "wan-loss"
cidr = "10.248.0.0/16"
[control]
bind = "0.0.0.0:$C_PORT"
secret = "$SECRET"
raft_dir = "$DIR/n$((i+1))/raft"
raft_id = $((i+1))
raft_bind = "0.0.0.0:$R_PORT"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $boot
raft_election_timeout_ms = $ELECTION_MS
[[control.raft_peers]]
id = 1
addr = "$IP1:$R_PORT"
[[control.raft_peers]]
id = 2
addr = "$IP2:$R_PORT"
[[control.raft_peers]]
id = 3
addr = "$IP3:$R_PORT"
[[control.join_tokens]]
token = "join-wan"
prefixes = ["192.168.252.0/24"]
TOML
  scp -q -o BatchMode=yes -o ConnectTimeout=6 "$TMP/ctrl$((i+1)).toml" "${hosts[$i]}:$DIR/ctrl$((i+1)).toml"
  sshx "${hosts[$i]}" "mkdir -p $DIR/n$((i+1))/state $DIR/n$((i+1))/raft; cd $DIR; nohup $BIN --config ctrl$((i+1)).toml > ctrl$((i+1)).log 2>&1 & echo \$! > ctrl$((i+1)).pid"
  log "started ctrl$((i+1))"
done

T0=$(python3 -c 'import time;print(time.time())')
L=""
for _ in $(seq 1 90); do
  for i in 0 1 2; do
    v=$(leader_of "$i")
    if [ -n "$v" ]; then L="$v"; break 2; fi
  done
  sleep 1
done
[ -n "$L" ] || { log "FAIL: no leader within 90s under loss"; exit 1; }
log "initial leader=$L after $(python3 -c "import time;print(round(time.time()-$T0,1))")s under loss"
TIMING=$(status_of "$((L-1))" | python3 -c 'import json,sys; r=json.load(sys.stdin).get("raft") or {}; print(r.get("election_timeout_min_ms"), r.get("heartbeat_interval_ms"), r.get("source"))')
log "raft timing: $TIMING"
[ "$TIMING" = "$ELECTION_MS $((ELECTION_MS / 4)) config" ] || { log "FAIL: unexpected raft timing $TIMING"; exit 1; }
JOIN='{"node_id":"0101010101010101010101010101010101010101010101010101010101010101","overlay_ip":"10.248.0.10","token":"join-wan"}'
LSA1='{"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":null,"links":[],"prefixes":[{"prefix":"192.168.252.0/24","metric":0}],"overlay_ip":"10.248.0.10","addrs":[]}'
post(){ sshx "${hosts[$2]}" "curl -fsS --max-time 20 -H 'x-stellaris-secret: $SECRET' -H 'content-type: application/json' -d '$1' 'http://127.0.0.1:$C_PORT$3'" >/dev/null; }
post "$JOIN" "$((L-1))" /v1/join || fail "join failed on leader $L"
post "$LSA1" "$((L-1))" /v1/lsa || fail "lsa write failed on leader $L"
log "joined member and wrote lsa=1 on leader $L"
snapshot_has_member "$((L-1))" || fail "snapshot missing member on leader $L"
log "snapshot members ok on leader"

OLD=$L
log "kill leader $OLD"
sshx "${hosts[$((OLD-1))]}" "kill -9 \$(cat $DIR/ctrl$OLD.pid)" || fail "could not kill leader $OLD"
T0=$(python3 -c 'import time;print(time.time())')
NL=""
for _ in $(seq 1 120); do
  for i in 0 1 2; do
    [ "$((i+1))" = "$OLD" ] && continue
    v=$(leader_of "$i")
    if [ -n "$v" ] && [ "$v" != "$OLD" ]; then NL="$v"; break 2; fi
  done
  sleep 0.5
done
[ -n "$NL" ] || { log "FAIL: no new leader within 60s under loss"; for i in 0 1 2; do sshx "${hosts[$i]}" "tail -5 $DIR/ctrl$((i+1)).log"; done; exit 1; }
log "new leader=$NL after $(python3 -c "import time;print(round(time.time()-$T0,1))")s"
LSA2='{"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":2,"zone":null,"links":[],"prefixes":[{"prefix":"192.168.252.0/24","metric":0}],"overlay_ip":"10.248.0.10","addrs":[]}'
post "$LSA2" "$((NL-1))" /v1/lsa || fail "lsa write failed on new leader $NL"
log "wrote lsa=2 on new leader"
snapshot_has_member "$((NL-1))" || fail "snapshot missing member after failover"
log "failover snapshot ok"
log "OK: 3-region controller HA survives $LOSS loss + $DELAY delay"
