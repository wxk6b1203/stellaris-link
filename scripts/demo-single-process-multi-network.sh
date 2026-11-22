#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-multinet.XXXXXX")"
BASE=$(( (RANDOM % 2000) + 54000 ))
cleanup(){ [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
for n in a b; do
  api=$([ "$n" = a ] && echo "$BASE" || echo "$((BASE+1))")
  ip=$([ "$n" = a ] && echo 10.210.0.1 || echo 10.211.0.1)
  cat > "$TMP/$n.toml" <<TOML
[node]
name = "node-$n"
state_dir = "$TMP/$n-state"
overlay_ip = "$ip"
[network]
name = "net-$n"
cidr = "$([ "$n" = a ] && echo 10.210.0.0/16 || echo 10.211.0.0/16)"
[api]
bind = "127.0.0.1:$api"
TOML
done
"$ROOT/target/debug/stellaris-agent" --config "$TMP/a.toml" --config "$TMP/b.toml" > "$TMP/agent.log" 2>&1 & PID=$!
sleep 3
STARTS=$(grep -c 'stellaris agent started' "$TMP/agent.log" || true)
if [[ "$STARTS" -ne 2 ]]; then
  echo "FAIL: expected 2 network runtimes, got $STARTS" >&2
  cat "$TMP/agent.log" >&2
  exit 1
fi
if ! kill -0 "$PID" 2>/dev/null; then
  echo "FAIL: multi-network agent exited" >&2; cat "$TMP/agent.log" >&2; exit 1
fi
echo "OK: one agent process runs two isolated network runtimes."
