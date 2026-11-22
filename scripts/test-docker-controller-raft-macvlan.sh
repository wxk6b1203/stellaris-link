#!/usr/bin/env bash
set -euo pipefail
# 3 real controller processes on real LAN IPs via Docker macvlan.
# Required: PARENT, SUBNET, GATEWAY, IP1, IP2, IP3, IP_CLIENT
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/release/stellaris-controller}"
: "${PARENT:?}" "${SUBNET:?}" "${GATEWAY:?}" "${IP1:?}" "${IP2:?}" "${IP3:?}" "${IP_CLIENT:?}"
[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-raft-macvlan.XXXXXX")"
NET="stellaris-ctrl-$$"
IPS=("$IP1" "$IP2" "$IP3")
cleanup(){ docker rm -f ctrl1 ctrl2 ctrl3 ctrl-client >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
SECRET="controller-secret"; RAFT_SECRET="raft-secret"
NODE="0101010101010101010101010101010101010101010101010101010101010101"
for i in 0 1 2; do
  mkdir -p "$TMP/n$i/state" "$TMP/n$i/raft"
  BOOT=false; [[ "$i" == 0 ]] && BOOT=true
  cat > "$TMP/n$i.toml" <<TOML
[node]
name = "c$((i+1))"
role = "controller"
state_dir = "/state"
overlay_ip = "10.7.0.$((i+1))"

[network]
name = "raft-macvlan"
cidr = "10.7.0.0/16"

[control]
bind = "0.0.0.0:4790$((i+1))"
secret = "$SECRET"
raft_dir = "/raft"
raft_id = $((i+1))
raft_bind = "0.0.0.0:4780$((i+1))"
raft_secret = "$RAFT_SECRET"
raft_bootstrap = $BOOT

[[control.raft_peers]]
id = 1
addr = "$IP1:47801"

[[control.raft_peers]]
id = 2
addr = "$IP2:47802"

[[control.raft_peers]]
id = 3
addr = "$IP3:47803"

[[control.join_tokens]]
token = "join-macvlan"
prefixes = ["192.168.201.0/24"]
TOML
done
docker network create -d macvlan --subnet="$SUBNET" --gateway="$GATEWAY" -o parent="$PARENT" "$NET" >/dev/null
for i in 0 1 2; do
  docker run -d --name "ctrl$((i+1))" --network "$NET" --ip "${IPS[$i]}" \
    -v "$BIN:/stellaris-controller:ro" -v "$TMP/n$i.toml:/config.toml:ro" \
    -v "$TMP/n$i/state:/state" -v "$TMP/n$i/raft:/raft" nginx:latest \
    /stellaris-controller --config /config.toml >/dev/null
done
docker run -d --name ctrl-client --network "$NET" --ip "$IP_CLIENT" nginx:latest sleep 3600 >/dev/null
req(){ docker exec ctrl-client curl -fsS "$@"; }
status(){ req -H "x-stellaris-secret: $SECRET" "http://$1:4790$2/v1/status"; }
leader(){ for i in 1 2 3; do status "${IPS[$((i-1))]}" "$i" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")' 2>/dev/null && return 0 || true; done; return 1; }
for _ in $(seq 1 100); do
  for i in 1 2 3; do
    if status "${IPS[$((i-1))]}" "$i" >/dev/null 2>&1; then
      L=$(status "${IPS[$((i-1))]}" "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      if [[ -n "$L" ]]; then echo "leader=$L"; break 2; fi
    fi
  done
  sleep 0.2
done
[[ -n "${L:-}" ]] || { echo "FAIL: no leader" >&2; for i in 1 2 3; do echo "--- c$i"; docker logs "ctrl$i" 2>&1 | tail -30; done; exit 1; }
JOIN=$(python3 - <<'PY'
import json
print(json.dumps({"node_id":"0101010101010101010101010101010101010101010101010101010101010101","overlay_ip":"10.7.0.20","token":"join-macvlan"}))
PY
)
req -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' -d "$JOIN" "http://${IPS[$((L-1))]}:4790$L/v1/join" >/dev/null
LSA=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":1,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.201.0/24","metric":0}],"overlay_ip":"10.7.0.20","addrs":[]}))
PY
)
req -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' -d "$LSA" "http://${IPS[$((L-1))]}:4790$L/v1/lsa" >/dev/null
sleep 1
req -H "x-stellaris-secret: $SECRET" "http://${IPS[$((L-1))]}:4790$L/v1/snapshot?node=$NODE" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("snapshot ok")'
docker rm -f "ctrl$L" >/dev/null
for _ in $(seq 1 100); do
  for i in 1 2 3; do
    [[ "$i" == "$L" ]] && continue
    if status "${IPS[$((i-1))]}" "$i" >/dev/null 2>&1; then
      NL=$(status "${IPS[$((i-1))]}" "$i" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leader") or "")')
      if [[ -n "$NL" && "$NL" != "$L" ]]; then echo "new leader=$NL"; break 2; fi
    fi
  done
  sleep 0.2
done
[[ -n "${NL:-}" ]] || { echo "FAIL: no new leader" >&2; for i in 1 2 3; do echo "--- c$i"; docker logs "ctrl$i" 2>&1 | tail -30; done; exit 1; }
LSA2=$(python3 - <<'PY'
import json
print(json.dumps({"origin":"0101010101010101010101010101010101010101010101010101010101010101","seq":2,"zone":None,"links":[],"prefixes":[{"prefix":"192.168.201.0/24","metric":0}],"overlay_ip":"10.7.0.20","addrs":[]}))
PY
)
req -H "x-stellaris-secret: $SECRET" -H 'content-type: application/json' -d "$LSA2" "http://${IPS[$((NL-1))]}:4790$NL/v1/lsa" >/dev/null
sleep 1
req -H "x-stellaris-secret: $SECRET" "http://${IPS[$((NL-1))]}:4790$NL/v1/snapshot?node=$NODE" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(m["node_id"]=="0101010101010101010101010101010101010101010101010101010101010101" for m in d["members"]), d; print("failover snapshot ok")'
echo "OK: 3 macvlan controller raft join/LSA/snapshot/failover works."
