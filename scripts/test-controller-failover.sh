#!/usr/bin/env bash
# A member configured with a Raft follower's HTTP URL must rotate to
# control.url + control.failover_urls and converge on the actual leader.
# Single-host loopback test; no root/TUN required.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
AGENT="$BIN_DIR/stellaris-agent"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$AGENT" && -x "$CTRL" ]] || {
  echo "missing release binaries in $BIN_DIR" >&2
  exit 1
}
DIR="${DIR:-/tmp/stellaris-failover}"
rm -rf "$DIR"; mkdir -p "$DIR"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$DIR"
}
trap cleanup EXIT
SECRET="failover-secret"
RAFT_SECRET="raft-secret"
for i in 1 2 3; do
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  boot=false; [[ "$i" == 1 ]] && boot=true
  cat > "$DIR/n$i.toml" <<TOML
[node]
name = "c$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.243.0.$i"
[network]
name = "failover"
cidr = "10.243.0.0/16"
[control]
bind = "127.0.0.1:$((49300 + i))"
secret = "$SECRET"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((49310 + i))"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
[api]
bind = "127.0.0.1:$((49320 + i))"
[transport]
disable_relay = true
[[control.raft_peers]]
id = 1
addr = "127.0.0.1:49311"
[[control.raft_peers]]
id = 2
addr = "127.0.0.1:49312"
[[control.raft_peers]]
id = 3
addr = "127.0.0.1:49313"
TOML
  RUST_LOG=info "$CTRL" --config "$DIR/n$i.toml" > "$DIR/n$i.log" 2>&1 &
  PIDS+=($!)
done

status() {
  curl -fsS -m 2 -H "x-stellaris-secret: $SECRET" \
    "http://127.0.0.1:$((49300 + $1))/v1/status" 2>/dev/null || true
}
LEADER=""
for _ in $(seq 1 120); do
  for i in 1 2 3; do
    L=$(status "$i" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null || true)
    [[ -n "$L" ]] && { LEADER="$L"; break; }
  done
  [[ -n "$LEADER" ]] && break
  sleep 0.25
done
[[ -n "$LEADER" ]] || { echo "FAIL: no leader" >&2; exit 1; }
FOLLOWER=$(for i in 1 2 3; do [[ "$i" != "$LEADER" ]] && { echo "$i"; break; }; done)
echo "leader=$LEADER follower=$FOLLOWER"

FAILOVER_LINES=""
for i in 1 2 3; do
  [[ "$i" == "$FOLLOWER" ]] && continue
  FAILOVER_LINES+="  \"http://127.0.0.1:$((49300 + i))\",\n"
done
cat > "$DIR/member.toml" <<TOML
[node]
name = "m1"
state_dir = "$DIR/member-state"
overlay_ip = "10.243.0.20"
[network]
name = "failover"
cidr = "10.243.0.0/16"
[control]
url = "http://127.0.0.1:$((49300 + FOLLOWER))"
failover_urls = [
$(printf "$FAILOVER_LINES")
]
secret = "$SECRET"
[api]
bind = "127.0.0.1:49340"
[transport]
disable_relay = true
TOML
MEMBER_ID=$("$AGENT" --config "$DIR/member.toml" --print-id)
RUST_LOG=info "$AGENT" --config "$DIR/member.toml" > "$DIR/member.log" 2>&1 &
PIDS+=($!)

APPLIED=""
for _ in $(seq 1 120); do
  model=$(curl -fsS -m 2 -H "x-stellaris-secret: $SECRET" \
    "http://127.0.0.1:$((49300 + LEADER))/v1/model" 2>/dev/null || true)
  if [[ -n "$model" ]] && echo "$model" | grep -q "$MEMBER_ID"; then
    APPLIED=1; break
  fi
  sleep 0.5
done
if [[ -z "$APPLIED" ]]; then
  echo "FAIL: member did not converge through failover" >&2
  echo "--- member.log" >&2; tail -40 "$DIR/member.log" >&2
  for i in 1 2 3; do echo "--- c$i.log" >&2; tail -20 "$DIR/n$i.log" >&2; done
  exit 1
fi
grep -q "rotating to the next controller endpoint" "$DIR/member.log" || {
  echo "FAIL: no endpoint rotation was logged" >&2
  tail -20 "$DIR/member.log" >&2
  exit 1
}
echo "OK: member rotated from follower $FOLLOWER to leader $LEADER"
