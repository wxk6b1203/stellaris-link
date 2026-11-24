#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/stellaris-controller}"
[[ -x "$BIN" ]] || { echo "build first: cargo build -p stellaris-agent --bin stellaris-controller" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-raft-3node.XXXXXX")"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
SECRET="controller-secret"
RAFT_SECRET="raft-secret"
NODE="0101010101010101010101010101010101010101010101010101010101010101"
# This lab runs on loopback, so use the configurable floor explicitly instead of
# the cross-region default (1000 ms). The script asserts the value is applied.
ELECTION_MS="${ELECTION_MS:-300}"
for i in 1 2 3; do
  mkdir -p "$TMP/n$i/raft" "$TMP/n$i/state"
  BOOT=false; [[ "$i" == 1 ]] && BOOT=true
  cat > "$TMP/n$i.toml" <<TOML
[node]
name = "c$i"
role = "controller"
state_dir = "$TMP/n$i/state"
overlay_ip = "10.7.0.$i"

[network]
name = "raft-demo"
cidr = "10.7.0.0/16"

[control]
bind = "127.0.0.1:4790$i"
secret = "$SECRET"
raft_dir = "$TMP/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:4780$i"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $BOOT
raft_election_timeout_ms = $ELECTION_MS

[[control.raft_peers]]
id = 1
addr = "127.0.0.1:47801"

[[control.raft_peers]]
id = 2
addr = "127.0.0.1:47802"

[[control.raft_peers]]
id = 3
addr = "127.0.0.1:47803"

[[control.join_tokens]]
token = "join-3node"
prefixes = ["192.168.200.0/24"]
TOML
  RUST_LOG=info "$BIN" --config "$TMP/n$i.toml" >"$TMP/n$i.log" 2>&1 &
  PIDS+=($!)
done
status(){ curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:4790$1/v1/status"; }
leader(){ for i in 1 2 3; do if status "$i" >/dev/null 2>&1; then status "$i" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("leader") or "")' 2>/dev/null && return 0 || true; fi; done; return 1; }
for _ in $(seq 1 100); do
  for i in 1 2 3; do
    if status "$i" >/dev/null 2>&1; then
      L=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      if [[ -n "$L" ]]; then echo "leader=$L"; break 2; fi
    fi
  done
  sleep 0.1
done
[[ -n "${L:-}" ]] || { echo "FAIL: no leader" >&2; for i in 1 2 3; do echo "--- n$i"; tail -20 "$TMP/n$i.log"; done; exit 1; }
# The configured TOML value must be the one Raft actually runs with.
read -r T_MIN T_MAX T_HB T_SRC < <(status "$L" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=d.get("raft") or {}; print(r.get("election_timeout_min_ms"), r.get("election_timeout_max_ms"), r.get("heartbeat_interval_ms"), r.get("source"))')
WANT="$ELECTION_MS $((ELECTION_MS * 2)) $((ELECTION_MS / 4)) config"
[[ "$T_MIN $T_MAX $T_HB $T_SRC" == "$WANT" ]] || {
  echo "FAIL: status raft timing '$T_MIN $T_MAX $T_HB $T_SRC', want '$WANT'" >&2; exit 1; }
for i in 1 2 3; do
  grep -q "raft election timing" "$TMP/n$i.log" || { echo "FAIL: n$i did not log raft timing" >&2; exit 1; }
done
echo "raft timing ok: min=${T_MIN}ms max=${T_MAX}ms heartbeat=${T_HB}ms source=$T_SRC"
# Out-of-range values are rejected at config load, not silently clamped.
BAD_DIR="$TMP/bad"; mkdir -p "$BAD_DIR/state"
cp "$TMP/n1.toml" "$BAD_DIR/bad.toml"
sed -i.bak "s/^raft_election_timeout_ms = .*/raft_election_timeout_ms = 10/" "$BAD_DIR/bad.toml"
if "$BIN" --config "$BAD_DIR/bad.toml" >"$BAD_DIR/bad.log" 2>&1; then
  echo "FAIL: out-of-range raft_election_timeout_ms was accepted" >&2; exit 1
fi
grep -q "raft_election_timeout_ms must be between" "$BAD_DIR/bad.log" || {
  echo "FAIL: unexpected error for out-of-range timing:" >&2; cat "$BAD_DIR/bad.log" >&2; exit 1; }
echo "invalid timing rejected: $(grep -o 'control.raft_election_timeout_ms must be between.*' "$BAD_DIR/bad.log" | head -1)"
# Omitting the key must resolve to the cross-region default (1000/2000/250).
DEF="$TMP/default"; mkdir -p "$DEF/state" "$DEF/raft"
cat > "$DEF/default.toml" <<TOML
[node]
name = "c-default"
role = "controller"
state_dir = "$DEF/state"
overlay_ip = "10.8.0.1"

[network]
name = "raft-default"
cidr = "10.8.0.0/16"

[control]
bind = "127.0.0.1:47799"
secret = "$SECRET"
raft_dir = "$DEF/raft"
raft_id = 1
raft_bind = "127.0.0.1:47798"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = true
TOML
RUST_LOG=info "$BIN" --config "$DEF/default.toml" >"$DEF/default.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
  curl -fsS --max-time 2 -H "x-stellaris-secret: $SECRET" http://127.0.0.1:47799/v1/status >/dev/null 2>&1 && break
  sleep 0.1
done
DEFAULT_TIMING=$(curl -fsS --max-time 3 -H "x-stellaris-secret: $SECRET" http://127.0.0.1:47799/v1/status \
  | python3 -c 'import json,sys;r=json.load(sys.stdin).get("raft") or {};print(r.get("election_timeout_min_ms"), r.get("election_timeout_max_ms"), r.get("heartbeat_interval_ms"), r.get("source"))')
[[ "$DEFAULT_TIMING" == "1000 2000 250 default-cross-region" ]] || {
  echo "FAIL: cross-region default timing not applied (status: $DEFAULT_TIMING)" >&2
  cat "$DEF/default.log" >&2; exit 1; }
echo "default timing ok: min=1000ms max=2000ms heartbeat=250ms source=default-cross-region"
# join and LSA on the leader
JOIN=$(python3 - <<'PY'
import json
print(json.dumps({"node_id":"0101010101010101010101010101010101010101010101010101010101010101","overlay_ip":"10.7.0.20","token":"join-3node"}))
PY
)
curl -fsS -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "$JOIN" "http://127.0.0.1:4790$L/v1/join" >/dev/null
LSA=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.200.0/24","metric":0}],"overlay_ip":"10.7.0.20","addrs":[]}))
PY
)
curl -fsS -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "$LSA" "http://127.0.0.1:4790$L/v1/lsa" >/dev/null
sleep 1
SNAP=$(curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:4790$L/v1/snapshot?node=$NODE")
echo "$SNAP" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("snapshot ok")'
# kill leader and wait for a new one
LEADER_PID=${PIDS[$((L-1))]}
kill -9 "$LEADER_PID"
for _ in $(seq 1 100); do
  for i in 1 2 3; do
    [[ "$i" == "$L" ]] && continue
    if status "$i" >/dev/null 2>&1; then
      NL=$(status "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      if [[ -n "$NL" && "$NL" != "$L" ]]; then echo "new leader=$NL"; break 2; fi
    fi
  done
  sleep 0.1
done
[[ -n "${NL:-}" ]] || { echo "FAIL: no new leader" >&2; for i in 1 2 3; do echo "--- n$i"; tail -20 "$TMP/n$i.log"; done; exit 1; }
LSA2=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":2,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.200.0/24","metric":0}],"overlay_ip":"10.7.0.20","addrs":[]}))
PY
)
curl -fsS -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "$LSA2" "http://127.0.0.1:4790$NL/v1/lsa" >/dev/null
sleep 1
SNAP2=$(curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:4790$NL/v1/snapshot?node=$NODE")
echo "$SNAP2" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("failover snapshot ok")'
# restart the crashed leader and require it to catch up as a follower
RUST_LOG=info "$BIN" --config "$TMP/n$L.toml" >>"$TMP/n$L.log" 2>&1 &
PIDS[$((L-1))]=$!
for _ in $(seq 1 100); do
  if status "$L" >/dev/null 2>&1; then
    OLD_LEADER=$(status "$L" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
    [[ "$OLD_LEADER" == "$NL" ]] && break
  fi
  sleep 0.1
done
[[ "${OLD_LEADER:-}" == "$NL" ]] || { echo "FAIL: restarted leader did not rejoin" >&2; tail -30 "$TMP/n$L.log"; exit 1; }
for _ in $(seq 1 100); do
  SEQ=$(curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:4790$L/v1/model" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("lsas",{}).get("0101010101010101010101010101010101010101010101010101010101010101",{}).get("seq",0))' 2>/dev/null || echo 0)
  [[ "$SEQ" == "2" ]] && break
  sleep 0.1
done
[[ "$SEQ" == "2" ]] || { echo "FAIL: restarted leader did not catch up (seq=$SEQ)" >&2; exit 1; }
echo "crash recovery ok"
echo "OK: 3-controller raft join/LSA/snapshot/failover/crash-recovery works."
