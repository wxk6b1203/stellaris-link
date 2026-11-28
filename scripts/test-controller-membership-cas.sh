#!/usr/bin/env bash
# Membership edits must reject a stale compare-and-swap voter set and expose
# the leader hint when sent to a follower.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-controller}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-cas.XXXXXX")"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
[[ -x "$BIN" ]] || { echo "missing controller binary: $BIN" >&2; exit 1; }
for i in 1 2 3; do
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  boot=false; [[ "$i" == 1 ]] && boot=true
  cat > "$DIR/n$i.toml" <<TOML
[node]
name = "m$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.247.0.$i"
[network]
name = "cas"
cidr = "10.247.0.0/16"
[control]
bind = "127.0.0.1:$((49600 + i))"
secret = "cas-secret"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((49610 + i))"
raft_secret = "raft-secret"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
[api]
bind = "127.0.0.1:$((49620 + i))"
[transport]
disable_relay = true
[[control.raft_peers]]
id = 1
addr = "127.0.0.1:49611"
[[control.raft_peers]]
id = 2
addr = "127.0.0.1:49612"
[[control.raft_peers]]
id = 3
addr = "127.0.0.1:49613"
TOML
  RUST_LOG=warn "$BIN" --config "$DIR/n$i.toml" > "$DIR/n$i.log" 2>&1 & PIDS+=($!)
done
LEADER=""
for _ in $(seq 1 200); do
  for i in 1 2 3; do
    body=$(curl -fsS -m 2 -H "x-stellaris-secret: cas-secret" "http://127.0.0.1:$((49600 + i))/v1/status" 2>/dev/null || true)
    [[ -n "$body" ]] || continue
    if [[ "$(echo "$body" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null)" == "$i" ]]; then LEADER=$i; break; fi
  done
  [[ -n "$LEADER" ]] && break
  sleep 0.25
done
[[ -n "$LEADER" ]] || { echo "FAIL: no leader" >&2; exit 1; }
FOLLOWER=$(( LEADER == 1 ? 2 : 1 ))
echo "leader=$LEADER follower=$FOLLOWER"
post() {
  local port=$1 body=$2
  curl -s -D "$DIR/headers" -o "$DIR/body" -w '%{http_code}' \
    -H "x-stellaris-secret: cas-secret" -H 'content-type: application/json' \
    --data "$body" "http://127.0.0.1:$port/v1/raft/membership"
}
STALE=$(post $((49600 + LEADER)) '{"voters":[{"id":1,"addr":"127.0.0.1:49611"}],"expected_voters":[999]}')
echo "leader stale CAS=$STALE body=$(cat "$DIR/body")"
[[ "$STALE" == 409 ]] || { echo "FAIL: stale CAS was accepted" >&2; exit 1; }
FORWARD=$(post $((49600 + FOLLOWER)) '{"voters":[{"id":1,"addr":"127.0.0.1:49611"}],"expected_voters":[1,2,3]}')
echo "follower forward=$FORWARD leader_header=$(awk 'BEGIN{IGNORECASE=1} /^x-stellaris-raft-leader:/{print $2}' "$DIR/headers" | tr -d '\r')"
[[ "$FORWARD" == 503 ]] || { echo "FAIL: follower did not return a leader hint status" >&2; exit 1; }
grep -qi '^x-stellaris-raft-leader:' "$DIR/headers" || {
  echo "FAIL: missing x-stellaris-raft-leader header" >&2; exit 1; }
echo "OK: membership CAS and follower leader hint"
