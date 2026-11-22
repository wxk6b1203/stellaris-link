#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-thr.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 53000 ))
C1=$BASE; C2=$((BASE+1)); MEMBER=$((BASE+2))
cleanup(){ for p in "${C1_PID:-}" "${C2_PID:-}" "${M_PID:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
mkctrl(){ local n=$1 api=$2
cat > "$TMP/$n.toml" <<TOML
[node]
name = "$n"
role = "controller"
state_dir = "$TMP/$n-state"
[network]
name = "threshold"
cidr = "10.121.0.0/16"
[control]
bind = "127.0.0.1:$api"
secret = "threshold-secret"
epoch = 1
[transport]
disable_relay = true
[api]
bind = "127.0.0.1:0"
TOML
}
mkctrl c1 "$C1"; mkctrl c2 "$C2"
C1ID=$("$ROOT/target/debug/stellaris-controller" --config "$TMP/c1.toml" --print-id)
C2ID=$("$ROOT/target/debug/stellaris-controller" --config "$TMP/c2.toml" --print-id)
cat > "$TMP/member.toml" <<TOML
[node]
name = "member"
state_dir = "$TMP/member-state"
overlay_ip = "10.121.0.1"
[network]
name = "threshold"
cidr = "10.121.0.0/16"
[control]
urls = ["http://127.0.0.1:$C1", "http://127.0.0.1:$C2"]
secret = "threshold-secret"
controller_keys = ["$C1ID", "$C2ID"]
controller_threshold = 2
[transport]
disable_relay = true
[api]
bind = "127.0.0.1:$MEMBER"
TOML
"$ROOT/target/debug/stellaris-controller" --config "$TMP/c1.toml" > "$TMP/c1.log" 2>&1 & C1_PID=$!
"$ROOT/target/debug/stellaris-controller" --config "$TMP/c2.toml" > "$TMP/c2.log" 2>&1 & C2_PID=$!
sleep 2
"$ROOT/target/debug/stellaris-agent" --config "$TMP/member.toml" > "$TMP/member.log" 2>&1 & M_PID=$!
sleep 8
if ! grep -q 'applied controller routes' "$TMP/member.log"; then
  echo "FAIL: member did not apply threshold snapshot" >&2
  tail -30 "$TMP/member.log" >&2; exit 1
fi
if grep -q 'not enough distinct controller manifest signatures\|not enough distinct' "$TMP/member.log"; then
  echo "FAIL: threshold not satisfied" >&2; exit 1
fi
echo "OK: member applied a 2-controller threshold snapshot."
