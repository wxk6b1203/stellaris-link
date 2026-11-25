#!/usr/bin/env bash
# Single-host verification of the post-audit controller state:
#   - routes replicated through Raft with deterministic ids
#   - signed enrollment from a real agent, approved through the admin API
#   - approved member replicated to every controller
#   - leader-side replicated LSA TTL expiry
#   - epoch monotonic across a leader change
# Requires the release binaries, no root, no netns.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
AGENT="$BIN_DIR/stellaris-agent"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$CTRL" && -x "$AGENT" ]] || { echo "missing release binaries in $BIN_DIR" >&2; exit 1; }
DIR="${DIR:-/tmp/stellaris-state-ha}"
rm -rf "$DIR"; mkdir -p "$DIR"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
SECRET="ctrl-secret"; ADMIN="admin-secret"; RAFT="raft-secret"
CTRL_KEYS=""
NODE="0202020202020202020202020202020202020202020202020202020202020202"
status(){ curl -fsS --max-time 5 2>/dev/null -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((48300+$1))/v1/status"; }
model(){ curl -fsS --max-time 5 -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((48300+$1))/v1/model"; }
leader(){
  for i in 1 2 3; do
    if status "$i" >/dev/null 2>&1; then
      local l; l=$(status "$i" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")')
      if [[ -n "$l" ]]; then echo "$l"; return 0; fi
    fi
  done
  return 1
}
wait_leader(){ for _ in $(seq 1 120); do local l; l=$(leader) && { echo "$l"; return 0; }; sleep 0.5; done; return 1; }
wait_new_leader(){
  local old=$1
  for _ in $(seq 1 200); do
    for i in 1 2 3; do
      [[ "$i" == "$old" ]] && continue
      local candidate
      candidate=$(status "$i" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null) || continue
      if [[ -n "$candidate" && "$candidate" != "$old" ]]; then echo "$candidate"; return 0; fi
    done
    sleep 0.25
  done
  return 1
}

for i in 1 2 3; do
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  boot=false; [[ "$i" == 1 ]] && boot=true
  cat > "$DIR/n$i.toml" <<TOML
[node]
name = "sc$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.250.0.$i"
[network]
name = "state-ha"
cidr = "10.250.0.0/16"
[control]
bind = "127.0.0.1:$((48300+i))"
secret = "$SECRET"
admin_secret = "$ADMIN"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((48200+i))"
raft_secret = "$RAFT"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
lsa_ttl_secs = 2
[[control.raft_peers]]
id = 1
addr = "127.0.0.1:48201"
[[control.raft_peers]]
id = 2
addr = "127.0.0.1:48202"
[[control.raft_peers]]
id = 3
addr = "127.0.0.1:48203"
TOML
  # Create the controller identity before startup so the agent config below can
  # trust every replica's credential/snapshot signing key.
  ID=$("$CTRL" --config "$DIR/n$i.toml" --print-id)
  CTRL_KEYS+="${CTRL_KEYS:+, }\"$ID\""
  RUST_LOG=info "$CTRL" --config "$DIR/n$i.toml" >"$DIR/n$i.log" 2>&1 &
  PIDS+=($!)
done
L=$(wait_leader) || { echo "FAIL: no leader" >&2; exit 1; }
echo "leader=$L"

echo '--- 1. routes replicate with deterministic ids'
curl -fsS --max-time 10 -H "x-stellaris-secret: $ADMIN" -H 'content-type: application/json' \
  -d "{\"prefix\":\"192.168.55.0/24\",\"via\":\"$NODE\",\"metric\":3}" \
  "http://127.0.0.1:$((48300+L))/v1/routes" >/dev/null
IDS=()
for i in 1 2 3; do
  RID=$(model "$i" | python3 -c 'import json,sys;m=json.load(sys.stdin);v=m["routes"].get("192.168.55.0/24");assert v, m["routes"];print(sorted(v.items())[0][0])')
  IDS+=("$RID")
done
[[ "${IDS[0]}" == "${IDS[1]}" && "${IDS[1]}" == "${IDS[2]}" ]] || { echo "FAIL: route missing/diverged: ${IDS[*]}" >&2; exit 1; }
echo "route present on all replicas (via=${IDS[0]})"

echo '--- 2. admin secret required for route writes'
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "{\"prefix\":\"192.168.56.0/24\",\"via\":\"$NODE\",\"metric\":1}" \
  "http://127.0.0.1:$((48300+L))/v1/routes")
[[ "$CODE" == "401" ]] || { echo "FAIL: member secret accepted for route write ($CODE)" >&2; exit 1; }
echo "member secret rejected for admin write"

echo '--- 3. signed enrollment is queued and approved by an admin'
mkdir -p "$DIR/member-state"
cat > "$DIR/member.toml" <<TOML
[node]
name = "member"
state_dir = "$DIR/member-state"
overlay_ip = "10.250.0.20"
[network]
name = "state-ha"
cidr = "10.250.0.0/16"
[network.auth]
mode = "controller"
[control]
url = "http://127.0.0.1:$((48300+L))"
secret = "$SECRET"
controller_keys = [$CTRL_KEYS]
credential_ttl_secs = 600
[api]
bind = "127.0.0.1:48320"
TOML
RUST_LOG=info "$AGENT" --config "$DIR/member.toml" >"$DIR/member.log" 2>&1 &
MEMBER_PID=$!
PIDS+=("$MEMBER_PID")
MEMBER_ID=$(for _ in $(seq 1 100); do
  curl -s --max-time 2 "http://127.0.0.1:48320/v1/status" >/dev/null 2>&1 && break
  sleep 0.1
done; curl -fsS --max-time 3 "http://127.0.0.1:48320/v1/status" | python3 -c 'import json,sys;print(json.load(sys.stdin)["node_id"])')
# The signed /v1/enroll queues the unknown node; an admin must approve it.
PENDING=""
for _ in $(seq 1 100); do
  PENDING=$(curl -fsS --max-time 3 -H "x-stellaris-secret: $ADMIN" \
    "http://127.0.0.1:$((48300+L))/v1/admissions" 2>/dev/null \
    | python3 -c 'import json,sys;print(" ".join(p["node"] for p in json.load(sys.stdin)["pending"]))' 2>/dev/null \
    || echo "")
  [[ " $PENDING " == *" $MEMBER_ID "* ]] && break
  sleep 0.1
done
[[ " $PENDING " == *" $MEMBER_ID "* ]] || {
  echo "FAIL: enrolled node not pending approval (pending: ${PENDING:-none})" >&2
  tail -30 "$DIR/member.log" >&2; exit 1; }
curl -fsS --max-time 10 -H "x-stellaris-secret: $ADMIN" -H 'content-type: application/json' \
  -d '{"prefixes":[]}' "http://127.0.0.1:$((48300+L))/v1/admissions/$MEMBER_ID/approve" >/dev/null
echo "approved enrollment ($MEMBER_ID)"
for i in 1 2 3; do
  for _ in $(seq 1 100); do
    model "$i" | grep -q "$MEMBER_ID" && break
    sleep 0.1
  done
  model "$i" | grep -q "$MEMBER_ID" || { echo "FAIL: approved member missing on replica $i" >&2; exit 1; }
done
echo "approved member replicated ($MEMBER_ID)"

echo '--- 4. replicated LSA TTL'
for _ in $(seq 1 60); do
  model "$L" | python3 -c 'import json,sys;m=json.load(sys.stdin);sys.exit(0 if m["lsas"] else 1)' && break
  sleep 0.5
done
model "$L" | python3 -c 'import json,sys;m=json.load(sys.stdin);assert m["lsas"], "member LSA never arrived";print("LSA present:", list(m["lsas"]))'
kill -9 "$MEMBER_PID" 2>/dev/null || true
EXPIRED=""
for _ in $(seq 1 40); do
  if model "$L" | python3 -c 'import json,sys;m=json.load(sys.stdin);sys.exit(0 if not m["lsas"] else 1)'; then EXPIRED=1; break; fi
  sleep 0.5
done
[[ -n "$EXPIRED" ]] || { echo "FAIL: LSA not expired after ttl+housekeeping window" >&2; exit 1; }
for i in 1 2 3; do
  model "$i" | python3 -c 'import json,sys;m=json.load(sys.stdin);assert not m["lsas"], m["lsas"]' || { echo "FAIL: expiry not replicated to $i" >&2; exit 1; }
done
echo "LSA expired on all replicas"

echo '--- 5. epoch stays monotonic across leader change'
EPOCH_BEFORE=$(status "$L" | python3 -c 'import json,sys;print(json.load(sys.stdin)["epoch"])')
kill -9 "${PIDS[$((L-1))]}" 2>/dev/null || true
NL=$(wait_new_leader "$L") || { echo "FAIL: no new leader" >&2; exit 1; }
for _ in $(seq 1 60); do
  EPOCH_AFTER=$(status "$NL" | python3 -c 'import json,sys;print(json.load(sys.stdin)["epoch"])')
  [[ "$EPOCH_AFTER" -ge "$EPOCH_BEFORE" ]] && break
  sleep 0.5
done
[[ "$EPOCH_AFTER" -ge "$EPOCH_BEFORE" ]] || { echo "FAIL: epoch rolled back ($EPOCH_BEFORE -> $EPOCH_AFTER)" >&2; exit 1; }
echo "epoch monotonic ($EPOCH_BEFORE -> $EPOCH_AFTER), new leader=$NL"
echo "OK: controller state replication, signed enrollment approval, LSA TTL and epoch verified"
