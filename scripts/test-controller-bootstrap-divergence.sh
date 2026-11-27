#!/usr/bin/env bash
# Three Raft replicas are started with DIFFERENT local [[control.members]]
# seeds. Only the leader's config must be replicated; every replica's model
# must converge to the same member set instead of each keeping its local seed.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-controller}"
DIR="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-bootstrap.XXXXXX")"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
[[ -x "$BIN" ]] || { echo "missing controller binary: $BIN" >&2; exit 1; }
SECRET=seed-secret
A=0101010101010101010101010101010101010101010101010101010101010101
B=0202020202020202020202020202020202020202020202020202020202020202
for i in 1 2 3; do
  mkdir -p "$DIR/n$i/raft" "$DIR/n$i/state"
  boot=false; [[ "$i" == 1 ]] && boot=true
  member=""
  case "$i" in
    1) member="$A" ;;
    2) member="$B" ;;
    3) member="" ;;
  esac
  cat > "$DIR/n$i.toml" <<TOML
[node]
name = "c$i"
role = "controller"
state_dir = "$DIR/n$i/state"
overlay_ip = "10.244.0.$i"
[network]
name = "bootstrap"
cidr = "10.244.0.0/16"
[control]
bind = "127.0.0.1:$((49400 + i))"
secret = "$SECRET"
raft_dir = "$DIR/n$i/raft"
raft_id = $i
raft_bind = "127.0.0.1:$((49410 + i))"
raft_secret = "raft-secret"
raft_bootstrap = $boot
raft_election_timeout_ms = 300
[api]
bind = "127.0.0.1:$((49420 + i))"
[transport]
disable_relay = true
[[control.raft_peers]]
id = 1
addr = "127.0.0.1:49411"
[[control.raft_peers]]
id = 2
addr = "127.0.0.1:49412"
[[control.raft_peers]]
id = 3
addr = "127.0.0.1:49413"
TOML
  if [[ -n "$member" ]]; then
    cat >> "$DIR/n$i.toml" <<TOML
[[control.members]]
node_id = "$member"
overlay_ip = "10.244.0.$((10 + i))"
prefixes = ["192.168.$i.0/24"]
TOML
  fi
  RUST_LOG=info "$BIN" --config "$DIR/n$i.toml" > "$DIR/n$i.log" 2>&1 & PIDS+=($!)
done
status() { curl -fsS -m 2 -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$((49400 + $1))/v1/status" 2>/dev/null || true; }
LEADER=""
for _ in $(seq 1 160); do
  for i in 1 2 3; do
    L=$(status "$i" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null || true)
    [[ -n "$L" ]] && { LEADER="$L"; break; }
  done
  [[ -n "$LEADER" ]] && break
  sleep 0.25
done
[[ -n "$LEADER" ]] || { echo "FAIL: no leader" >&2; exit 1; }
sleep 8
python3 - "$SECRET" <<'PY'
import json, sys, urllib.request
secret = sys.argv[1]
sets = []
for i in (1, 2, 3):
    req = urllib.request.Request(
        f"http://127.0.0.1:{49400 + i}/v1/model",
        headers={"x-stellaris-secret": secret},
    )
    model = json.load(urllib.request.urlopen(req, timeout=3))
    sets.append(sorted(model["members"].keys()))
print("member sets:", sets)
assert sets[0] == sets[1] == sets[2], f"replicas diverged: {sets}"
assert len(sets[0]) == 1, f"expected exactly the leader's one seed, got {sets[0]}"
PY
echo "OK: replicas converged to the leader's bootstrap seed (no local divergence)"
