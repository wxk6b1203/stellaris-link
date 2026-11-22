#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-ctrl-ha.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 30000 ))
C1=$BASE
C2=$((BASE + 1))
MEMBER_API=$((BASE + 2))

cleanup() {
  for p in "${C1_PID:-}" "${C2_PID:-}" "${MEMBER_PID:-}"; do
    [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

for n in 1 2; do
  port=$([ "$n" = 1 ] && echo "$C1" || echo "$C2")
  cat > "$TMP/ctrl$n.toml" <<TOML
[node]
name = "ctrl$n"
role = "controller"
state_dir = "$TMP/ctrl$n-state"

[network]
name = "ha-demo"
cidr = "10.105.0.0/16"

[control]
bind = "127.0.0.1:$port"
secret = "ha-secret"
epoch = 5

[api]
bind = "127.0.0.1:0"
TOML
done

cat > "$TMP/member.toml" <<TOML
[node]
name = "member"
state_dir = "$TMP/member-state"
overlay_ip = "10.105.0.1"

[network]
name = "ha-demo"
cidr = "10.105.0.0/16"

[control]
urls = ["http://127.0.0.1:$C1", "http://127.0.0.1:$C2"]
secret = "ha-secret"

[transport]
disable_relay = true

[api]
bind = "127.0.0.1:$MEMBER_API"
TOML

"$ROOT/target/debug/stellaris-controller" --config "$TMP/ctrl1.toml" > "$TMP/ctrl1.log" 2>&1 & C1_PID=$!
"$ROOT/target/debug/stellaris-controller" --config "$TMP/ctrl2.toml" > "$TMP/ctrl2.log" 2>&1 & C2_PID=$!
sleep 2
"$ROOT/target/debug/stellaris-agent" --config "$TMP/member.toml" > "$TMP/member.log" 2>&1 & MEMBER_PID=$!
sleep 5

for port in "$C1" "$C2"; do
  echo "--- controller $port ---"
  curl -s -H 'x-stellaris-secret: ha-secret' "http://127.0.0.1:$port/v1/status"
  echo
done

ACK1="$(curl -s -H 'x-stellaris-secret: ha-secret' "http://127.0.0.1:$C1/v1/status")"
ACK2="$(curl -s -H 'x-stellaris-secret: ha-secret' "http://127.0.0.1:$C2/v1/status")"
if [[ "$ACK1" != *'"acks":1'* || "$ACK2" != *'"acks":1'* ]]; then
  echo "FAIL: member did not ACK both controllers" >&2
  exit 1
fi

echo "--- killing controller 1; member should keep running against controller 2 ---"
kill "$C1_PID" 2>/dev/null || true
sleep 4
if ! "$ROOT/target/debug/stellaris" --api "http://127.0.0.1:$MEMBER_API" status >/dev/null 2>&1; then
  echo "FAIL: member API died" >&2
  exit 1
fi
echo "OK: active-active controller fanout (pre-Raft) is working."
