#!/usr/bin/env bash
# iroh control must go through Raft: an LSA sent to a follower endpoint must
# not be applied locally, and the same LSA sent to the leader must replicate.
# Single host, no root needed.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
AGENT="$BIN_DIR/stellaris-agent"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$CTRL" && -x "$AGENT" ]] || { echo "missing release binaries in $BIN_DIR" >&2; exit 1; }
DIR="${DIR:-/tmp/stellaris-iroh-raft}"
rm -rf "$DIR"; mkdir -p "$DIR"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
SECRET="ctrl-secret"; RAFT="raft-secret"
status(){ curl -fsS --max-time 5 2>/dev/null -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((48500+$1))/v1/status"; }
model(){ curl -fsS --max-time 5 -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((48500+$1))/v1/model"; }
leader_of(){ status "$1" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null || true; }
wait_leader(){ for _ in $(seq 1 120); do for i in 1 2 3; do local l; l=$(leader_of "$i"); [[ -n "$l" ]] && { echo "$l"; return 0; }; done; sleep 0.5; done; return 1; }

for i in 1 2 3; do
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  boot=false; [[ "$i" == 1 ]] && boot=true
  cat > "$DIR/n$i.toml" <<TOML
[node]
name = "ic$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.252.0.$i"
[network]
name = "iroh-raft"
cidr = "10.252.0.0/16"
[control]
bind = "127.0.0.1:$((48500+i))"
secret = "$SECRET"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((48400+i))"
raft_secret = "$RAFT"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
iroh_port = $((48600+i))
[transport]
disable_relay = true
[[control.raft_peers]]
id = 1
addr = "127.0.0.1:48401"
[[control.raft_peers]]
id = 2
addr = "127.0.0.1:48402"
[[control.raft_peers]]
id = 3
addr = "127.0.0.1:48403"
TOML
  EID=$("$CTRL" --config "$DIR/n$i.toml" --print-id)
  echo "$EID" > "$DIR/n$i.id"
  RUST_LOG=info "$CTRL" --config "$DIR/n$i.toml" >"$DIR/n$i.log" 2>&1 &
  PIDS+=($!)
done
L=$(wait_leader) || { echo "FAIL: no leader" >&2; exit 1; }
FOLLOWER=$(for i in 1 2 3; do [[ "$i" != "$L" ]] && { echo "$i"; break; }; done)
echo "leader=$L follower=$FOLLOWER"

member_config(){
  cat > "$DIR/member.toml" <<TOML
[node]
name = "iroh-member"
state_dir = "$DIR/member-state"
overlay_ip = "10.252.0.20"
[network]
name = "iroh-raft"
cidr = "10.252.0.0/16"
[control]
endpoint_id = "$1"
addrs = ["127.0.0.1:$2"]
secret = "$SECRET"
[api]
bind = "127.0.0.1:48620"
[transport]
disable_relay = true
TOML
}
start_member(){ RUST_LOG=info "$AGENT" --config "$DIR/member.toml" >"$DIR/member-$1.log" 2>&1 & AGENT_PID=$!; }
stop_member(){ kill -9 "$AGENT_PID" 2>/dev/null || true; }

echo '--- 1. LSA sent to a follower iroh endpoint must not be applied'
mkdir -p "$DIR/member-state"
member_config "$(cat "$DIR/n$FOLLOWER.id")" "$((48600+FOLLOWER))"
start_member follower
sleep 8
if model "$FOLLOWER" | python3 -c 'import json,sys;m=json.load(sys.stdin);sys.exit(0 if m["lsas"] else 1)'; then
  echo "FAIL: follower applied an iroh LSA locally" >&2
  exit 1
fi
grep -qE "raft write failed|RAFT|raft" "$DIR/member-follower.log" || true
echo "follower did not apply the iroh LSA"
stop_member

echo '--- 2. The same LSA sent to the leader must replicate to all replicas'
member_config "$(cat "$DIR/n$L.id")" "$((48600+L))"
start_member leader
APPLIED=""
for _ in $(seq 1 60); do
  if model "$L" | python3 -c 'import json,sys;m=json.load(sys.stdin);sys.exit(0 if m["lsas"] else 1)'; then APPLIED=1; break; fi
  sleep 0.5
done
[[ -n "$APPLIED" ]] || { echo "FAIL: leader never applied the iroh LSA" >&2; tail -20 "$DIR/member-leader.log" >&2; exit 1; }
for i in 1 2 3; do
  model "$i" | python3 -c 'import json,sys;m=json.load(sys.stdin);assert m["lsas"], "lsa missing"' || {
    echo "FAIL: LSA not replicated to $i" >&2; exit 1; }
done
echo "iroh LSA applied on the leader and replicated to all replicas"
stop_member
echo "OK: iroh control path goes through Raft"
