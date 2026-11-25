#!/usr/bin/env bash
# Bulk-persistence benchmark for a single-node Raft controller.
#
# Writes N LSAs (default 5100, 24 prefixes each) over HTTP, prints import
# time, on-disk sizes, then restarts the controller and prints recovery time.
# Used to compare the append-only log + snapshot/WAL implementation with the
# earlier full-JSON rewrite (5,100 LSAs took ~5m49s and rewrote the whole
# state after every entry).
set -euo pipefail

BIN="${BIN:-$(pwd)/target/release/stellaris-controller}"
DIR="${DIR:-/tmp/stellaris-persist}"
N="${N:-5100}"
THREADS="${THREADS:-8}"
PORT=5801
SECRET="persist-secret"

rm -rf "$DIR"; mkdir -p "$DIR"
cleanup() { pkill -f "[s]tellaris-controller --config $DIR/controller.toml" 2>/dev/null || true; }
trap cleanup EXIT

cat > "$DIR/controller.toml" <<TOML
[node]
name = "persist"
role = "controller"
state_dir = "$DIR/state"

[network]
name = "persist"
cidr = "10.0.0.0/8"

[control]
bind = "127.0.0.1:$PORT"
secret = "$SECRET"
raft_dir = "$DIR/raft"
raft_secret = "raft-secret"
raft_id = 1
raft_bind = "127.0.0.1:0"
raft_bootstrap = true
raft_election_timeout_ms = 300
lsa_ttl_secs = 3600

[transport]
disable_relay = true
TOML

start() {
  setsid "$BIN" --config "$DIR/controller.toml" >"$DIR/controller.log" 2>&1 &
  for _ in $(seq 1 200); do
    curl -fsS --max-time 1 -H "x-stellaris-secret: $SECRET" \
      "http://127.0.0.1:$PORT/v1/status" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "controller did not start" >&2
  tail -20 "$DIR/controller.log" >&2
  return 1
}

echo "== start controller"
START=$(python3 -c 'import time;print(time.time())')
start
READY=$(python3 -c 'import time;print(time.time())')
echo "startup_seconds=$(python3 -c "print(f'{$READY-$START:.2f}')")"

echo "== import $N LSAs with $THREADS threads"
IMPORT_START=$(python3 -c 'import time;print(time.time())')
python3 - "$N" "$THREADS" "$PORT" "$SECRET" <<'PY'
import hashlib, json, sys, threading, urllib.request
n, threads, port, secret = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
errors = []
lock = threading.Lock()

def worker(start):
    for i in range(start, n, threads):
        origin = hashlib.sha256(f"node-{i}".encode()).hexdigest()
        prefixes = [
            {"prefix": f"10.{i % 250}.{j}.{k}/32", "metric": j}
            for j in range(24)
            for k in (i % 7,)
        ]
        lsa = {
            "origin": origin,
            "seq": 1,
            "zone": None,
            "links": [],
            "prefixes": prefixes,
            "overlay_ip": None,
            "addrs": [],
        }
        body = json.dumps(lsa).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/lsa",
            data=body,
            headers={"content-type": "application/json", "x-stellaris-secret": secret},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                if response.status != 200:
                    raise RuntimeError(f"status {response.status}")
        except Exception as error:  # noqa: BLE001
            with lock:
                errors.append(str(error))
                if len(errors) > 10:
                    return

workers = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
for thread in workers:
    thread.start()
for thread in workers:
    thread.join()
if errors:
    print("import errors:", errors[:5], file=sys.stderr)
    sys.exit(1)
PY
IMPORT_END=$(python3 -c 'import time;print(time.time())')
echo "import_seconds=$(python3 -c "print(f'{$IMPORT_END-$IMPORT_START:.2f}')")"

MODEL=$(curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$PORT/v1/model")
echo "$MODEL" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("generation=",d["generation"],"lsas=",len(d["lsas"]))'
echo "raft_dir_bytes=$(du -sb "$DIR/raft" | cut -f1)"
find "$DIR/raft" -maxdepth 2 -type f -printf '%P %s\n' | sort | head -20

echo "== restart controller"
pkill -f "[s]tellaris-controller --config $DIR/controller.toml" 2>/dev/null || true
sleep 1
RESTART_START=$(python3 -c 'import time;print(time.time())')
start
RESTART_END=$(python3 -c 'import time;print(time.time())')
echo "restart_seconds=$(python3 -c "print(f'{$RESTART_END-$RESTART_START:.2f}')")"
MODEL=$(curl -fsS -H "x-stellaris-secret: $SECRET" "http://127.0.0.1:$PORT/v1/model")
echo "$MODEL" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("recovered_generation=",d["generation"],"recovered_lsas=",len(d["lsas"]))'

echo "OK: persistence benchmark complete"
