#!/usr/bin/env bash
# Approval-only Raft controller must enforce LSA membership as soon as an
# admission exists. Regression test for the startup-only `strict_membership`
# bug: before the fix a Raft controller that started with no [[control.members]]
# accepted LSAs for any origin/prefix forever.
set -euo pipefail
BIN_DIR="${BIN_DIR:-$(pwd)/target/release}"
AGENT="$BIN_DIR/stellaris-agent"
CTRL="$BIN_DIR/stellaris-controller"
[[ -x "$AGENT" && -x "$CTRL" ]] || {
  echo "missing release binaries in $BIN_DIR (cargo build --release --bins)" >&2
  exit 1
}
DIR="${DIR:-/tmp/stellaris-approval-auth}"
rm -rf "$DIR"; mkdir -p "$DIR/c/raft" "$DIR/c/state" "$DIR/m"
SECRET=member-secret; ADMIN=admin-secret
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$DIR"
}
trap cleanup EXIT

cat > "$DIR/c.toml" <<TOML
[node]
name = "c1"
role = "controller"
state_dir = "$DIR/c/state"
overlay_ip = "10.246.0.1"
[network]
name = "approval-auth"
cidr = "10.246.0.0/16"
[control]
bind = "127.0.0.1:49000"
secret = "$SECRET"
allow_unsigned_lsa = true
admin_secret = "$ADMIN"
raft_dir = "$DIR/c/raft"
raft_id = 1
raft_bind = "127.0.0.1:49001"
raft_secret = "raft-secret"
raft_bootstrap = true
raft_election_timeout_ms = 300
[transport]
disable_relay = true
TOML
EID=$("$CTRL" --config "$DIR/c.toml" --print-id)
RUST_LOG=info "$CTRL" --config "$DIR/c.toml" > "$DIR/c.log" 2>&1 & PIDS+=($!)

for _ in $(seq 1 80); do
  curl -fsS -m 1 -H "x-stellaris-secret: $SECRET" http://127.0.0.1:49000/v1/status >/dev/null 2>&1 && break
  sleep 0.25
done

cat > "$DIR/m.toml" <<TOML
[node]
name = "m1"
state_dir = "$DIR/m/state"
overlay_ip = "10.246.0.20"
[network]
name = "approval-auth"
cidr = "10.246.0.0/16"
[network.auth]
mode = "controller"
[control]
url = "http://127.0.0.1:49000"
secret = "$SECRET"
controller_keys = ["$EID"]
[api]
bind = "127.0.0.1:49020"
[transport]
disable_relay = true
TOML
RUST_LOG=info "$AGENT" --config "$DIR/m.toml" > "$DIR/m.log" 2>&1 & PIDS+=($!)
MEMBER=""
for _ in $(seq 1 80); do
  MEMBER=$(curl -fsS -m 1 http://127.0.0.1:49020/v1/status 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("node_id",""))' 2>/dev/null || true)
  [[ -n "$MEMBER" ]] && break
  sleep 0.25
done
[[ -n "$MEMBER" ]] || { echo "FAIL: member did not start" >&2; tail -20 "$DIR/m.log" >&2; exit 1; }
echo "member=$MEMBER"

ROGUE=0303030303030303030303030303030303030303030303030303030303030303
lsa_body() {
  printf '{"origin":"%s","seq":%s,"zone":null,"links":[],"prefixes":[{"prefix":"%s","metric":0}],"overlay_ip":"%s","addrs":[]}' \
    "$1" "$2" "$3" "$4"
}
code=$(curl -s -o /dev/null -w '%{http_code}' -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "$(lsa_body "$ROGUE" 1 10.99.0.0/24 10.246.0.99)" http://127.0.0.1:49000/v1/lsa)
echo "rogue LSA before approval: HTTP $code (want 403)"
[[ "$code" == "403" ]] || { echo "FAIL: controller accepted an unapproved origin" >&2; exit 1; }

# The signed /v1/enroll is queued; approve it as an admin.
for _ in $(seq 1 100); do
  PENDING=$(curl -fsS -m 2 -H "x-stellaris-secret: $ADMIN" http://127.0.0.1:49000/v1/admissions 2>/dev/null \
    | python3 -c 'import json,sys;print(" ".join(p["node"] for p in json.load(sys.stdin)["pending"]))' 2>/dev/null || true)
  [[ " $PENDING " == *" $MEMBER "* ]] && break
  sleep 0.2
done
curl -fsS -m 5 -H "x-stellaris-secret: $ADMIN" -H 'content-type: application/json' \
  -d '{"prefixes":[]}' "http://127.0.0.1:49000/v1/admissions/$MEMBER/approve" >/dev/null
echo "approved $MEMBER"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "$(lsa_body "$MEMBER" 2 10.99.0.0/24 10.246.0.20)" http://127.0.0.1:49000/v1/lsa)
echo "out-of-grant LSA: HTTP $code (want 403)"
[[ "$code" == "403" ]] || { echo "FAIL: approved member advertised an unauthorized prefix" >&2; exit 1; }

code=$(curl -s -o /dev/null -w '%{http_code}' -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' \
  -d "$(lsa_body "$MEMBER" 3 10.246.0.20/32 10.246.0.20)" http://127.0.0.1:49000/v1/lsa)
echo "own-overlay LSA: HTTP $code (want 200)"
[[ "$code" == "200" ]] || { echo "FAIL: member's own overlay LSA was rejected" >&2; exit 1; }

echo "OK: approval-only Raft controller enforces membership for LSAs"
