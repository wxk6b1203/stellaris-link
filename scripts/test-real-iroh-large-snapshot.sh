#!/usr/bin/env bash
# iroh control must sync a controller model larger than the old 4 MiB frame cap.
# Builds a >4 MiB model with a few large LSAs, then has an iroh-only member
# fetch the snapshot and ACK it.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
AGENT="$BIN_DIR/stellaris-agent"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$CTRL" && -x "$AGENT" ]] || { echo "missing release binaries in $BIN_DIR" >&2; exit 1; }
DIR="${DIR:-/tmp/stellaris-iroh-large}"
rm -rf "$DIR"; mkdir -p "$DIR"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$DIR"; }
trap cleanup EXIT
SECRET="ctrl-secret"; RAFT="raft-secret"
status(){ curl -fsS --max-time 5 2>/dev/null -H "x-stellaris-secret: $SECRET" http://127.0.0.1:48800/v1/status; }
mkdir -p "$DIR/raft" "$DIR/state"
cat > "$DIR/ctrl.toml" <<TOML
[node]
name = "large-snapshot"
role = "controller"
state_dir = "$DIR/state"
overlay_ip = "10.254.0.1"
[network]
name = "iroh-large"
cidr = "10.254.0.0/16"
[control]
bind = "127.0.0.1:48800"
secret = "$SECRET"
raft_dir = "$DIR/raft"
raft_id = 1
raft_bind = "127.0.0.1:48802"
raft_secret = "$RAFT"
raft_bootstrap = true
raft_election_timeout_ms = 300
iroh_port = 48801
lsa_ttl_secs = 3600
[transport]
disable_relay = true
TOML
EID=$("$CTRL" --config "$DIR/ctrl.toml" --print-id)
RUST_LOG=info "$CTRL" --config "$DIR/ctrl.toml" >"$DIR/ctrl.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
  curl -fsS --max-time 2 -H "x-stellaris-secret: $SECRET" http://127.0.0.1:48800/v1/status >/dev/null 2>&1 && break
  sleep 0.1
done

cat > "$DIR/push.py" <<'PY'
import json, sys, threading, urllib.request
count, prefixes, port = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
secret = sys.argv[4]
errors = []
def one(i):
    body = json.dumps({
        "origin": f"{5000+i:064x}",
        "seq": 1,
        "zone": None,
        "links": [],
        "prefixes": [{"prefix": f"10.{i%200}.{(j//256)%256}.{j%256}/24", "metric": 0}
                     for j in range(prefixes)],
        "overlay_ip": None,
        "addrs": [],
    }).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/lsa", data=body,
        headers={"content-type": "application/json", "x-stellaris-secret": secret})
    try:
        urllib.request.urlopen(req, timeout=30).read()
    except Exception as e:
        errors.append(str(e))
ts = [threading.Thread(target=one, args=(i,)) for i in range(count)]
[t.start() for t in ts]
[t.join() for t in ts]
print(f"pushed={count} errors={len(errors)} first={errors[:1]}")
PY
python3 "$DIR/push.py" 300 800 48800 "$SECRET"
sleep 2
SIZE=$(stat -c %s "$DIR/raft/raft-state.json")
echo "controller raft-state.json bytes=$SIZE"
[[ "$SIZE" -gt 4194304 ]] || { echo "FAIL: model is not larger than the old 4 MiB cap" >&2; exit 1; }

mkdir -p "$DIR/member-state"
cat > "$DIR/member.toml" <<TOML
[node]
name = "iroh-member"
state_dir = "$DIR/member-state"
overlay_ip = "10.254.0.20"
[network]
name = "iroh-large"
cidr = "10.254.0.0/16"
[control]
endpoint_id = "$EID"
addrs = ["127.0.0.1:48801"]
secret = "$SECRET"
[api]
bind = "127.0.0.1:48820"
[transport]
disable_relay = true
TOML
RUST_LOG=info "$AGENT" --config "$DIR/member.toml" >"$DIR/member.log" 2>&1 &
PIDS+=($!)
ACKED=""
for _ in $(seq 1 120); do
  ACKS=$(status | python3 -c 'import json,sys;print(json.load(sys.stdin).get("acks",0))' 2>/dev/null || echo 0)
  [[ "${ACKS:-0}" -ge 1 ]] && { ACKED=1; break; }
  sleep 0.5
done
[[ -n "$ACKED" ]] || { echo "FAIL: iroh member never ACKed the large snapshot" >&2; tail -20 "$DIR/member.log" >&2; exit 1; }
if grep -q "control frame too large" "$DIR/member.log"; then
  echo "FAIL: member hit the control frame limit" >&2; exit 1
fi
echo "iroh member ACKed a $((SIZE / 1024 / 1024)) MiB snapshot ($(status | python3 -c 'import json,sys;print("acks=",json.load(sys.stdin).get("acks"))'))"
echo "OK: iroh control syncs models above the old 4 MiB frame cap"
