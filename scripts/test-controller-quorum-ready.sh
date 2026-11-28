#!/usr/bin/env bash
# A Raft leader that loses quorum must stop reporting ready. Followers may
# still report ready (they forward writes); a single-node cluster stays ready.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-controller}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-quorum.XXXXXX")"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
[[ -x "$BIN" ]] || { echo "missing controller binary: $BIN" >&2; exit 1; }
SECRET=quorum-secret
start_node() {
  local i=$1
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  local boot=false; [[ "$i" == 1 ]] && boot=true
  cat > "$DIR/n$i.toml" <<TOML
[node]
name = "q$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.246.0.$i"
[network]
name = "quorum"
cidr = "10.246.0.0/16"
[control]
bind = "127.0.0.1:$((49500 + i))"
secret = "$SECRET"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((49510 + i))"
raft_secret = "raft-secret"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
[api]
bind = "127.0.0.1:$((49520 + i))"
[transport]
disable_relay = true
[[control.raft_peers]]
id = 1
addr = "127.0.0.1:49511"
[[control.raft_peers]]
id = 2
addr = "127.0.0.1:49512"
[[control.raft_peers]]
id = 3
addr = "127.0.0.1:49513"
TOML
  RUST_LOG=warn "$BIN" --config "$DIR/n$i.toml" > "$DIR/n$i.log" 2>&1 & PIDS+=($!)
}
code() { curl -s -o /dev/null -w '%{http_code}' -m 2 "http://127.0.0.1:$((49500 + $1))/readyz"; }
for i in 1 2 3; do start_node "$i"; done
LEADER=""
for _ in $(seq 1 200); do
  for i in 1 2 3; do
    body=$(curl -fsS -m 2 -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((49500 + i))/v1/status" 2>/dev/null || true)
    [[ -n "$body" ]] || continue
    if [[ "$(echo "$body" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null)" == "$i" ]]; then
      LEADER=$i; break
    fi
  done
  [[ -n "$LEADER" ]] && break
  sleep 0.25
done
[[ -n "$LEADER" ]] || { echo "FAIL: no leader" >&2; exit 1; }
echo "leader=$LEADER"
[[ "$(code "$LEADER")" == "200" ]] || { echo "FAIL: leader not ready initially" >&2; exit 1; }
# Stop both followers; the leader has no quorum and its lease must expire.
for i in 1 2 3; do
  [[ "$i" == "$LEADER" ]] && continue
  kill -9 "${PIDS[$((i - 1))]}" 2>/dev/null || true
  wait "${PIDS[$((i - 1))]}" 2>/dev/null || true
done
sleep 6
STATUS=$(code "$LEADER")
echo "leader after quorum loss: $STATUS"
[[ "$STATUS" == "503" ]] || { echo "FAIL: old leader still ready without quorum" >&2; exit 1; }
# Restart followers; readiness must recover.
for i in 1 2 3; do [[ "$i" == "$LEADER" ]] && continue; start_node "$i"; done
for _ in $(seq 1 200); do
  [[ "$(code "$LEADER")" == "200" ]] && break
  sleep 0.25
done
[[ "$(code "$LEADER")" == "200" ]] || { echo "FAIL: leader did not recover readiness" >&2; exit 1; }
echo "leader after quorum recovery: 200"
echo "OK: /readyz tracks quorum lease"
