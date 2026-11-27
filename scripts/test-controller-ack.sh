#!/usr/bin/env bash
# Regression test for two controller ACK bugs:
#   1. HTTP ACK used the stale `ControllerState.epoch` (0 in Raft mode), so
#      every member ACK was 409 after the leader published the wall-clock epoch;
#   2. an ACK advanced the topology generation, so an idle iroh member caused a
#      full snapshot + ACK + Raft write every two seconds.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
AGENT="$BIN_DIR/stellaris-agent"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$AGENT" && -x "$CTRL" ]] || {
  echo "missing release binaries in $BIN_DIR (cargo build --release --bins)" >&2
  exit 1
}
DIR="${DIR:-/tmp/stellaris-ack-test}"
rm -rf "$DIR"; mkdir -p "$DIR/c/raft" "$DIR/c/state" "$DIR/m"
SECRET=ack-secret
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$DIR"
}
trap cleanup EXIT
status() { curl -fsS -m 2 -H "x-stellaris-secret: $SECRET" http://127.0.0.1:49100/v1/status; }
NODE=0101010101010101010101010101010101010101010101010101010101010101

cat > "$DIR/c.toml" <<TOML
[node]
name = "c1"
role = "controller"
state_dir = "$DIR/c/state"
overlay_ip = "10.245.0.1"
[network]
name = "ack-test"
cidr = "10.245.0.0/16"
[control]
bind = "127.0.0.1:49100"
secret = "$SECRET"
raft_dir = "$DIR/c/raft"
raft_id = 1
raft_bind = "127.0.0.1:49101"
raft_secret = "raft-secret"
raft_bootstrap = true
raft_election_timeout_ms = 300
iroh_port = 49102
[transport]
disable_relay = true
TOML
EID=$("$CTRL" --config "$DIR/c.toml" --print-id)
RUST_LOG=info "$CTRL" --config "$DIR/c.toml" > "$DIR/c.log" 2>&1 & PIDS+=($!)

for _ in $(seq 1 120); do status >/dev/null 2>&1 && break; sleep 0.25; done
EPOCH=""
for _ in $(seq 1 120); do
  EPOCH=$(status | python3 -c 'import json,sys;print(json.load(sys.stdin)["epoch"])')
  [[ "$EPOCH" -gt 0 ]] && break
  sleep 0.5
done
[[ -n "$EPOCH" && "$EPOCH" -gt 0 ]] || { echo "FAIL: controller never published its epoch" >&2; exit 1; }
GEN=$(status | python3 -c 'import json,sys;print(json.load(sys.stdin)["generation"])')

echo "-- HTTP ACK epoch (epoch=$EPOCH)"
body="{\"node\":\"$NODE\",\"generation\":$GEN,\"epoch\":$EPOCH}"
code=$(curl -s -o "$DIR/ack.out" -w '%{http_code}' -H "x-stellaris-secret: $SECRET" \
  -H 'content-type: application/json' -d "$body" http://127.0.0.1:49100/v1/ack)
echo "correct epoch: HTTP $code (want 200)"
[[ "$code" == "200" ]] || { echo "FAIL: ACK with the snapshot epoch was rejected" >&2; cat "$DIR/ack.out" >&2; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H "x-stellaris-secret: $SECRET" \
  -H 'content-type: application/json' -d "{\"node\":\"$NODE\",\"generation\":$GEN,\"epoch\":0}" \
  http://127.0.0.1:49100/v1/ack)
echo "stale epoch:   HTTP $code (want 409)"
[[ "$code" == "409" ]] || { echo "FAIL: stale epoch was accepted" >&2; exit 1; }

echo "-- idle iroh member must not advance generation"
cat > "$DIR/m.toml" <<TOML
[node]
name = "m1"
state_dir = "$DIR/m/state"
overlay_ip = "10.245.0.20"
[network]
name = "ack-test"
cidr = "10.245.0.0/16"
[control]
endpoint_id = "$EID"
addrs = ["127.0.0.1:49102"]
secret = "$SECRET"
[api]
bind = "127.0.0.1:49120"
[transport]
disable_relay = true
TOML
RUST_LOG=info "$AGENT" --config "$DIR/m.toml" > "$DIR/m.log" 2>&1 & PIDS+=($!)
ACKED=0
for _ in $(seq 1 120); do
  ACKED=$(status | python3 -c 'import json,sys;print(json.load(sys.stdin)["acks"])' 2>/dev/null || echo 0)
  [[ "$ACKED" -ge 1 ]] && break
  sleep 0.5
done
[[ "$ACKED" -ge 1 ]] || { echo "FAIL: iroh member never ACKed" >&2; tail -20 "$DIR/m.log" >&2; exit 1; }

# Let the member's own LSA/epoch housekeeping settle, then require a stable
# generation for five seconds with no configuration changes.
last=""
for _ in $(seq 1 20); do
  now=$(status | python3 -c 'import json,sys;print(json.load(sys.stdin)["generation"])')
  [[ "$now" == "$last" ]] && { stable=$now; break; }
  last=$now
  sleep 0.5
done
stable=${stable:-$last}
sleep 5
after=$(status | python3 -c 'import json,sys;print(json.load(sys.stdin)["generation"])')
echo "generation before=$stable after=$after"
[[ "$stable" == "$after" ]] || {
  echo "FAIL: generation advanced while the member was idle (ACK feedback loop)" >&2
  exit 1
}
echo "OK: HTTP ACK epoch and idle-member generation are stable"
