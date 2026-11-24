#!/usr/bin/env bash
# Dynamic Raft membership end-to-end: start 3 voters, add a 4th controller as
# a learner, promote it with change_membership, then prove a 4-voter cluster
# still commits with one follower down.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$CTRL" ]] || { echo "missing $CTRL" >&2; exit 1; }
DIR="${DIR:-/tmp/stellaris-membership}"
rm -rf "$DIR"; mkdir -p "$DIR"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
SECRET="member-secret"; ADMIN="admin-secret"; RAFT="raft-secret"
status(){ curl -fsS --max-time 5 2>/dev/null -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((48700+$1))/v1/status"; }
model(){ curl -fsS --max-time 5 -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((48700+$1))/v1/model"; }
leader_of(){ status "$1" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null || true; }
wait_leader(){ for _ in $(seq 1 160); do for i in 1 2 3 4; do local l; l=$(leader_of "$i"); [[ -n "$l" ]] && { echo "$l"; return 0; }; done; sleep 0.5; done; return 1; }

write_config(){
  local i=$1 peers=$2 boot=$3
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  {
    cat <<TOML
[node]
name = "mc$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.253.0.$i"
[network]
name = "membership"
cidr = "10.253.0.0/16"
[control]
bind = "127.0.0.1:$((48700+i))"
secret = "$SECRET"
admin_secret = "$ADMIN"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((48600+i))"
raft_secret = "$RAFT"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
TOML
    for p in $peers; do
      cat <<TOML
[[control.raft_peers]]
id = $p
addr = "127.0.0.1:$((48600+p))"
TOML
    done
  } > "$DIR/n$i.toml"
  "$CTRL" --config "$DIR/n$i.toml" --print-id > "$DIR/n$i.id"
  RUST_LOG=info "$CTRL" --config "$DIR/n$i.toml" >"$DIR/n$i.log" 2>&1 &
  PIDS+=($!)
}
write_config 1 "1 2 3" true
write_config 2 "1 2 3" false
write_config 3 "1 2 3" false
L=$(wait_leader) || { echo "FAIL: no initial leader" >&2; exit 1; }
echo "initial leader=$L (3 voters)"

echo '--- add a 4th controller as learner'
write_config 4 "1 2 3 4" false
sleep 1
LEARNER=$(curl -s -o "$DIR/learner.out" -w '%{http_code}' --max-time 20 -H "x-stellaris-secret: $ADMIN" \
  -H 'content-type: application/json' -d '{"id":4,"addr":"127.0.0.1:48604"}' \
  "http://127.0.0.1:$((48700+L))/v1/raft/learner")
[[ "$LEARNER" == "200" ]] || { echo "FAIL: add_learner returned $LEARNER: $(cat "$DIR/learner.out")" >&2; exit 1; }
echo "learner 4 added"

echo '--- promote to 4 voters'
MEMBERSHIP=$(curl -s -o "$DIR/membership.out" -w '%{http_code}' --max-time 20 -H "x-stellaris-secret: $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"voters":[{"id":1,"addr":"127.0.0.1:48601"},{"id":2,"addr":"127.0.0.1:48602"},{"id":3,"addr":"127.0.0.1:48603"},{"id":4,"addr":"127.0.0.1:48604"}]}' \
  "http://127.0.0.1:$((48700+L))/v1/raft/membership")
[[ "$MEMBERSHIP" == "200" ]] || { echo "FAIL: change_membership returned $MEMBERSHIP: $(cat "$DIR/membership.out")" >&2; exit 1; }
for _ in $(seq 1 80); do
  G4=$(status 4 | python3 -c 'import json,sys;print(json.load(sys.stdin).get("generation"))' 2>/dev/null || true)
  [[ -n "$G4" ]] && break
  sleep 0.5
done
echo "4-voter cluster formed (ctrl4 generation=$G4)"

echo '--- a route must replicate to the new voter'
ROUTE='{"prefix":"192.168.88.0/24","via":"0404040404040404040404040404040404040404040404040404040404040404","metric":2}'
curl -fsS --max-time 20 -H "x-stellaris-secret: $ADMIN" -H 'content-type: application/json' \
  -d "$ROUTE" "http://127.0.0.1:$((48700+L))/v1/routes" >/dev/null
for _ in $(seq 1 60); do
  if model 4 | grep -q '192.168.88.0/24'; then CONVERGED=1; break; fi
  sleep 0.5
done
[[ -n "${CONVERGED:-}" ]] || { echo "FAIL: route did not reach ctrl4" >&2; exit 1; }
echo "route replicated to the new voter"

echo '--- one follower down leaves quorum (4 voters -> 3)'
kill -9 "${PIDS[1]}" 2>/dev/null || true
sleep 2
ROUTE2='{"prefix":"192.168.89.0/24","via":"0404040404040404040404040404040404040404040404040404040404040404","metric":3}'
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "x-stellaris-secret: $ADMIN" \
  -H 'content-type: application/json' -d "$ROUTE2" \
  "http://127.0.0.1:$((48700+L))/v1/routes")
[[ "$CODE" == "200" ]] || { echo "FAIL: write failed with one follower down ($CODE)" >&2; exit 1; }
echo "write accepted with one follower down ($CODE)"
echo "OK: dynamic membership (3 -> 4 voters, learner promotion) verified"
