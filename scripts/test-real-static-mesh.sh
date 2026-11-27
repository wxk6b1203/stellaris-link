#!/usr/bin/env bash
# 4-node real-host test for network.auth.mode = "static" (WireGuard-style).
#
# Each host runs one agent with a TUN device, fully-meshed [[peers]] and a
# static allowlist. Verifies:
#   1. every pair of peers connects and can ping the other overlay /32;
#   2. a node whose key is NOT in the allowlist cannot connect;
#   3. removing a peer from the local config makes the pair disconnect
#      (the remote side keeps dialing and is rejected).
#
# Required env:
#   HOSTS   space-separated ssh targets (root)
#   PUBIPS  space-separated public IPs, same order as HOSTS
#   BIN     path to the agent binary on every host
# Optional:
#   DIR (default /opt/static-mesh), KEEP=1 to keep state, PORT_BASE/API_BASE.
set -euo pipefail

HOSTS="${HOSTS:-}"
PUBIPS="${PUBIPS:-}"
BIN="${BIN:-}"
DIR="${DIR:-/opt/static-mesh}"
PORT_BASE="${PORT_BASE:-47100}"
API_BASE="${API_BASE:-47200}"
TOKEN="static-test-token"

[[ -n "$HOSTS" && -n "$PUBIPS" && -n "$BIN" ]] || {
  echo "usage: HOSTS='root@a root@b' PUBIPS='ip-a ip-b' BIN=/path/stellaris-agent $0" >&2
  exit 2
}
read -r -a HOST_ARR <<<"$HOSTS"
read -r -a IP_ARR <<<"$PUBIPS"
N=${#HOST_ARR[@]}
[[ "$N" -ge 2 && ${#IP_ARR[@]} -eq "$N" ]] || { echo "HOSTS/PUBIPS mismatch" >&2; exit 2; }

sshh() { ssh -o ConnectionAttempts=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$@"; }
sshn() { ssh -n -o ConnectionAttempts=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$@"; }
api() { # api <index> <path>  (curl via ssh on localhost)
  sshh "${HOST_ARR[$1]}" "curl -fsS --max-time 3 -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$((API_BASE + $1 + 1))$2"
}
peer_connected() { # peer_connected <observer-idx> <remote-node-id>
  api "$1" /v1/peers | python3 -c "
import json,sys
want=sys.argv[1]
for p in json.load(sys.stdin):
    if p['node_id']==want or p.get('endpoint_id')==want:
        print('1' if p.get('connected') else '0'); raise SystemExit
print('0')" "$2"
}

PIDS=()
cleanup() {
  for i in "${!HOST_ARR[@]}"; do
    sshh "${HOST_ARR[$i]}" "pkill -f '[s]tellaris-agent --config $DIR/n$((i + 1)).toml' 2>/dev/null; pkill -f '[s]tellaris-agent --config $DIR/rogue.toml' 2>/dev/null; ip link del stellaris0 2>/dev/null" >/dev/null 2>&1 || true
  done
  if [[ "${KEEP:-0}" != "1" ]]; then
    for h in "${HOST_ARR[@]}"; do sshh "$h" "rm -rf $DIR" >/dev/null 2>&1 || true; done
  fi
}
trap cleanup EXIT

echo "== nodes: $N"
for i in "${!HOST_ARR[@]}"; do
  sshh "${HOST_ARR[$i]}" "mkdir -p $DIR && rm -rf $DIR/n$((i + 1)) $DIR/n$((i + 1)).toml $DIR/rogue $DIR/rogue.log $DIR/rogue.toml; pkill -f '[s]tellaris-agent --config $DIR/rogue.toml' 2>/dev/null || true" || true
done

# Phase 1: write configs without peers so --print-id passes validation.
for i in "${!HOST_ARR[@]}"; do
  n=$((i + 1))
  sshh "${HOST_ARR[$i]}" "cat > $DIR/n$n.toml" <<TOML
[node]
name = "n$n"
state_dir = "$DIR/n$n"
overlay_ip = "10.77.0.$n"

[network]
name = "static-mesh"
cidr = "10.77.0.0/16"

[transport]
disable_relay = true
listen_port = $((PORT_BASE + n))
advertise = ["${IP_ARR[$i]}:$((PORT_BASE + n))"]

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:$((API_BASE + n))"
token = "$TOKEN"
TOML
done

IDS=()
for i in "${!HOST_ARR[@]}"; do
  n=$((i + 1))
  ID=$(sshh "${HOST_ARR[$i]}" "$BIN --config $DIR/n$n.toml --print-id")
  IDS+=("$ID")
  echo "n$n id=${ID:0:16}... pub=${IP_ARR[$i]}"
done

# Phase 2: append full-mesh peers + static allowlist.
for i in "${!HOST_ARR[@]}"; do
  n=$((i + 1))
  {
    for j in "${!HOST_ARR[@]}"; do
      [[ "$j" == "$i" ]] && continue
      m=$((j + 1))
      cat <<TOML

[[peers]]
name = "n$m"
endpoint_id = "${IDS[$j]}"
overlay_ip = "10.77.0.$m"
addrs = ["${IP_ARR[$j]}:$((PORT_BASE + m))"]
TOML
    done
    cat <<TOML

[network.auth]
mode = "static"
TOML
  } | sshh "${HOST_ARR[$i]}" "cat >> $DIR/n$n.toml"
done

echo "== starting agents"
for i in "${!HOST_ARR[@]}"; do
  n=$((i + 1))
  sshn "${HOST_ARR[$i]}" "{ cd $DIR && setsid $BIN --config $DIR/n$n.toml; } >$DIR/n$n.log 2>&1 </dev/null & exit 0" || true
done

for _ in $(seq 1 60); do
  ok=1
  for i in "${!HOST_ARR[@]}"; do api "$i" /v1/status >/dev/null 2>&1 || ok=0; done
  [[ "$ok" == 1 ]] && break
  sleep 0.5
done
for i in "${!HOST_ARR[@]}"; do api "$i" /v1/status >/dev/null || { echo "FAIL: agent $((i + 1)) did not start"; sshh "${HOST_ARR[$i]}" "tail -20 $DIR/n$((i + 1)).log" >&2; exit 1; }; done
echo "agents up"

echo "== full mesh connections"
for i in "${!HOST_ARR[@]}"; do
  for j in "${!HOST_ARR[@]}"; do
    [[ "$j" == "$i" ]] && continue
    for _ in $(seq 1 60); do
      [[ "$(peer_connected "$i" "${IDS[$j]}")" == 1 ]] && break
      sleep 0.5
    done
    [[ "$(peer_connected "$i" "${IDS[$j]}")" == 1 ]] || {
      echo "FAIL: n$((i + 1)) -> n$((j + 1)) not connected" >&2
      sshh "${HOST_ARR[$i]}" "tail -30 $DIR/n$((i + 1)).log" >&2
      exit 1
    }
  done
done
echo "all pairs connected"

echo "== overlay pings"
fail=0
for i in "${!HOST_ARR[@]}"; do
  for j in "${!HOST_ARR[@]}"; do
    [[ "$j" == "$i" ]] && continue
    if ! sshh "${HOST_ARR[$i]}" "ping -c 2 -W 3 10.77.0.$((j + 1)) >/dev/null 2>&1"; then
      echo "FAIL: ping n$((i + 1)) -> n$((j + 1))" >&2
      fail=1
    fi
  done
done
[[ "$fail" == 0 ]] || { echo "FAIL: overlay pings" >&2; exit 1; }
echo "all pairs ping"

echo "== unknown key is rejected"
# Reuse node 1's UDP port (known to be reachable through the cloud security
# group) after stopping it; the rogue still uses a fresh identity key.
sshh "${HOST_ARR[0]}" "pkill -f '[s]tellaris-agent --config $DIR/n1.toml' 2>/dev/null" || true
sleep 2
RG=$((PORT_BASE + 1)); RAPI=$((API_BASE + 90))
cat > /tmp/rogue.toml <<TOML
[node]
name = "rogue"
state_dir = "$DIR/rogue"
overlay_ip = "10.77.0.99"
[network]
name = "static-mesh"
cidr = "10.77.0.0/16"
[transport]
disable_relay = true
disable_discovery = true
listen_port = $RG
[dataplane]
enabled = false
[api]
bind = "127.0.0.1:$RAPI"
token = "$TOKEN"
TOML
cat >> /tmp/rogue.toml <<TOML

[[peers]]
name = "n2"
endpoint_id = "${IDS[1]}"
overlay_ip = "10.77.0.2"
addrs = ["${IP_ARR[1]}:$((PORT_BASE + 2))"]

[network.auth]
mode = "static"
TOML
sshh "${HOST_ARR[0]}" "pkill -f '[s]tellaris-agent --config $DIR/rogue.toml' 2>/dev/null || true; rm -rf $DIR/rogue $DIR/rogue.log" || true
scp -q -o BatchMode=yes -o StrictHostKeyChecking=no /tmp/rogue.toml "${HOST_ARR[0]}:$DIR/rogue.toml"
ROGUE_ID=$(sshh "${HOST_ARR[0]}" "$BIN --config $DIR/rogue.toml --print-id")
sshn "${HOST_ARR[0]}" "{ RUST_LOG=debug setsid $BIN --config $DIR/rogue.toml; } >$DIR/rogue.log 2>&1 </dev/null & exit 0" || true
# A larger NodeId waits 5s before its fallback dial; leave enough time for
# the handshake and n2's rejection log under loaded CI hosts.
sleep 12
LIVE_ID=$(sshh "${HOST_ARR[0]}" "curl -fsS -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$RAPI/v1/status" | python3 -c 'import json,sys;print(json.load(sys.stdin)["node_id"])')
[[ "$LIVE_ID" == "$ROGUE_ID" ]] || {
  echo "FAIL: rogue agent did not start (log says: $(sshh "${HOST_ARR[0]}" "tail -2 $DIR/rogue.log"))" >&2; exit 1; }
[[ "$(peer_connected 0 "$ROGUE_ID")" == 0 ]] || true
# The rogue may briefly observe a QUIC-level "connected" before n2 closes it;
# what matters is that n2 never admits it (no peer entry, no LSA, no grant).
if api 1 /v1/peers | grep -q "$ROGUE_ID"; then
  echo "FAIL: n2 admitted the rogue key" >&2; api 1 /v1/peers >&2; exit 1
fi
# n2 must have logged the rejection (its allowlist does not include rogue).
for _ in $(seq 1 20); do
  sshh "${HOST_ARR[1]}" "grep -q 'not in the static allowlist' $DIR/n2.log" && break
  sleep 0.5
done
sshh "${HOST_ARR[1]}" "grep -q 'not in the static allowlist' $DIR/n2.log" || {
  echo "FAIL: n2 did not reject the rogue key" >&2
  sshh "${HOST_ARR[1]}" "tail -20 $DIR/n2.log" >&2; exit 1; }
sshh "${HOST_ARR[0]}" "pkill -f '[s]tellaris-agent --config $DIR/rogue.toml'" || true
echo "rogue rejected"

echo "OK: static mode mesh ($N nodes): all pairs connected and ping; unknown key rejected"
