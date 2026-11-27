#!/usr/bin/env bash
# Real-host IPAM test: controller allocates overlay addresses to members.
#
# Verifies:
#   1. node.ipam = "auto" enrolls without a static address and receives one
#      from the controller-signed credential;
#   2. every member gets a unique lease, the TUN device is configured with the
#      allocated address and all pairs can ping;
#   3. restarting an agent keeps the same address (cached credential);
#   4. revoking a member releases its lease into quarantine and the remaining
#      members still work.
#
# Required env:
#   HOSTS   space-separated ssh targets (root); first host runs the controller
#   PUBIPS  public IPs, same order
#   BIN     agent binary path on every host
#   CTRL    controller binary path on the first host
set -euo pipefail

HOSTS="${HOSTS:-}"
PUBIPS="${PUBIPS:-}"
BIN="${BIN:-/usr/local/bin/stellaris-agent}"
CTRL="${CTRL:-/usr/local/bin/stellaris-controller}"
DIR="${DIR:-/opt/ipam-mesh}"
CTRL_PORT=5801
PORT_BASE=5900
API_BASE=47600
SECRET="member-secret"
ADMIN="admin-secret"
TOKEN="ipam-test-token"

[[ -n "$HOSTS" && -n "$PUBIPS" ]] || {
  echo "usage: HOSTS='root@a root@b ...' PUBIPS='ip-a ip-b ...' $0" >&2
  exit 2
}
read -r -a HOST_ARR <<<"$HOSTS"
read -r -a IP_ARR <<<"$PUBIPS"
N=${#HOST_ARR[@]}
[[ "$N" -ge 2 && ${#IP_ARR[@]} -eq "$N" ]] || { echo "HOSTS/PUBIPS mismatch" >&2; exit 2; }

sshh() { ssh -o ConnectionAttempts=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$@"; }
sshn() { ssh -n -o ConnectionAttempts=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$@"; }
# Quick probe used in polling loops: one attempt, short timeout.
sshq() { ssh -n -o ConnectionAttempts=1 -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$@"; }
api() { # api <host-index> <port> <path>
  sshh "${HOST_ARR[$1]}" "curl -fsS --max-time 3 -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$2$3"
}

cleanup() {
  for i in "${!HOST_ARR[@]}"; do
    sshh "${HOST_ARR[$i]}" "pkill -9 -f '[s]tellaris-agent --config $DIR' 2>/dev/null; sleep 0.5; ip link del stellaris0 2>/dev/null" >/dev/null 2>&1 || true
  done
  sshh "${HOST_ARR[0]}" "pkill -f '[s]tellaris-controller --config $DIR/controller.toml' 2>/dev/null" >/dev/null 2>&1 || true
  if [[ "${KEEP:-0}" != "1" ]]; then
    for h in "${HOST_ARR[@]}"; do sshh "$h" "rm -rf $DIR" >/dev/null 2>&1 || true; done
  fi
}
trap cleanup EXIT

# Make reruns deterministic: stop anything left from a previous attempt.
for h in "${HOST_ARR[@]}"; do
  sshh "$h" "pkill -f '[s]tellaris-agent --config $DIR' 2>/dev/null; pkill -f '[s]tellaris-controller --config $DIR' 2>/dev/null" >/dev/null 2>&1 || true
done
sleep 1

echo "== controller on ${IP_ARR[0]}"
sshh "${HOST_ARR[0]}" "mkdir -p $DIR && rm -rf $DIR/ctrl-state"
sshh "${HOST_ARR[0]}" "cat > $DIR/controller.toml" <<TOML
[node]
name = "ctrl"
role = "controller"
state_dir = "$DIR/ctrl-state"

[network]
name = "ipam-mesh"
cidr = "10.66.0.0/16"

[control]
bind = "0.0.0.0:$CTRL_PORT"
secret = "$SECRET"
admin_secret = "$ADMIN"
credential_ttl_secs = 600

[control.ipam]
[[control.ipam.pools]]
id = "mesh"
cidr = "10.66.0.0/24"
lease_secs = 600
quarantine_secs = 30

[transport]
disable_relay = true

TOML
CTRL_ID=$(sshh "${HOST_ARR[0]}" "$CTRL --config $DIR/controller.toml --print-id")
echo "controller id=${CTRL_ID:0:16}..."
sshn "${HOST_ARR[0]}" "{ setsid $CTRL --config $DIR/controller.toml; } >$DIR/controller.log 2>&1 </dev/null & exit 0" || true
for _ in $(seq 1 60); do
  sshq "${HOST_ARR[0]}" "curl -fsS --max-time 2 -H 'x-stellaris-secret: $SECRET' http://127.0.0.1:$CTRL_PORT/v1/status" >/dev/null 2>&1 && break
  sleep 0.5
done
sshh "${HOST_ARR[0]}" "curl -fsS --max-time 3 -H 'x-stellaris-secret: $SECRET' http://127.0.0.1:$CTRL_PORT/v1/status" >/dev/null || {
  echo "FAIL: controller did not start" >&2; sshh "${HOST_ARR[0]}" "tail -20 $DIR/controller.log" >&2; exit 1; }
echo "controller up"

echo "== agents with node.ipam = \"auto\""
declare -a NODE_IDS=()
for i in $(seq 1 $((N - 1))); do
  h=${HOST_ARR[$i]}
  ip=${IP_ARR[$i]}
  sshh "$h" "mkdir -p $DIR && rm -rf $DIR/n$i $DIR/n$i.toml"
  sshh "$h" "cat > $DIR/n$i.toml" <<TOML
[node]
name = "n$i"
state_dir = "$DIR/n$i"
ipam = "auto"

[network]
name = "ipam-mesh"
cidr = "10.66.0.0/16"

[network.auth]
mode = "controller"

[control]
url = "http://${IP_ARR[0]}:$CTRL_PORT"
secret = "$SECRET"
controller_keys = ["$CTRL_ID"]
credential_ttl_secs = 600
discover_members = true

[transport]
disable_relay = true
listen_port = $((PORT_BASE + i))
advertise = ["$ip:$((PORT_BASE + i))"]

[routing]
link_state = true

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:$((API_BASE + i))"
token = "$TOKEN"
TOML
  NODE_IDS+=("$(sshh "$h" "$BIN --config $DIR/n$i.toml --print-id")")
  sshn "$h" "{ setsid $BIN --config $DIR/n$i.toml; } >$DIR/n$i.log 2>&1 </dev/null & exit 0" || true
done

echo "== approving pending enrollments in host order"
for i in $(seq 1 $((N - 1))); do
  NODE=${NODE_IDS[$((i - 1))]}
  for _ in $(seq 1 120); do
    sshh "${HOST_ARR[0]}" "curl -fsS --max-time 3 -H 'x-stellaris-secret: $ADMIN' http://127.0.0.1:$CTRL_PORT/v1/admissions" \
      | grep -q "$NODE" && break
    sleep 0.5
  done
  code=$(sshh "${HOST_ARR[0]}" "curl -s -o /tmp/approve.out -w '%{http_code}' --max-time 5 -H 'x-stellaris-secret: $ADMIN' -H 'content-type: application/json' -d '{\"prefixes\":[]}' http://127.0.0.1:$CTRL_PORT/v1/admissions/$NODE/approve")
  [[ "$code" == "200" ]] || { echo "FAIL: approve n$i returned $code" >&2; sshh "${HOST_ARR[0]}" "cat /tmp/approve.out" >&2; exit 1; }
  echo "approved n$i ${NODE:0:12}..."
done

# The agent API only starts once the data plane has an address, which happens
# after approval and the next enrollment poll.
for i in $(seq 1 $((N - 1))); do
  ok=0
  for _ in $(seq 1 120); do
    sshq "${HOST_ARR[$i]}" "curl -fsS --max-time 2 -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$((API_BASE + i))/v1/status" >/dev/null 2>&1 && { ok=1; break; }
    sleep 0.5
  done
  [[ "$ok" == 1 ]] || { echo "FAIL: agent $i did not start" >&2; sshh "${HOST_ARR[$i]}" "tail -30 $DIR/n$i.log" >&2; exit 1; }
done
echo "agents up"

echo "== waiting for credentials and TUN addresses"
declare -a OVERLAYS=()
for i in $(seq 1 $((N - 1))); do
  reached=0
  for _ in $(seq 1 80); do
    addr=$(api "$i" $((API_BASE + i)) /v1/status | python3 -c '
import json,sys
d=json.load(sys.stdin)
c=d.get("credential") or {}
print(c.get("overlay_ip") or "")')
    if [[ -n "$addr" ]]; then
      OVERLAYS+=("$addr")
      reached=1
      break
    fi
    sleep 0.5
  done
  [[ "$reached" == 1 ]] || { echo "FAIL: n$i got no credential/address" >&2; sshh "${HOST_ARR[$i]}" "tail -30 $DIR/n$i.log" >&2; exit 1; }
  expected="10.66.0.$i"
  [[ "${OVERLAYS[$((i - 1))]}" == "$expected" ]] || {
    echo "FAIL: n$i got ${OVERLAYS[$((i - 1))]}, expected $expected" >&2; exit 1; }
  for _ in $(seq 1 40); do
    sshh "${HOST_ARR[$i]}" "ip -4 addr show stellaris0 2>/dev/null | grep -q '$expected'" && break
    sleep 0.5
  done
  sshh "${HOST_ARR[$i]}" "ip -4 addr show stellaris0 2>/dev/null | grep -q '$expected'" || {
    echo "FAIL: n$i TUN missing $expected" >&2; sshh "${HOST_ARR[$i]}" "ip -4 addr show stellaris0" >&2; exit 1; }
  echo "n$i -> $expected"
done

echo "== ipam leases"
LEASES=$(sshh "${HOST_ARR[0]}" "curl -fsS -H 'x-stellaris-secret: $ADMIN' http://127.0.0.1:$CTRL_PORT/v1/ipam/leases")
COUNT=$(echo "$LEASES" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["leases"]))')
[[ "$COUNT" == "$((N - 1))" ]] || { echo "FAIL: expected $((N - 1)) leases, got $COUNT" >&2; echo "$LEASES" >&2; exit 1; }
echo "$COUNT leases"

echo "== waiting for the peer mesh"
for i in $(seq 1 $((N - 1))); do
  connected=0
  for _ in $(seq 1 120); do
    connected=$(api "$i" $((API_BASE + i)) /v1/peers | python3 -c '
import json,sys
print(sum(1 for p in json.load(sys.stdin) if p.get("connected")))' 2>/dev/null || echo 0)
    [[ "$connected" -ge "$((N - 2))" ]] && break
    sleep 0.5
  done
  [[ "$connected" -ge "$((N - 2))" ]] || {
    echo "FAIL: n$i only has $connected connected peers" >&2
    sshh "${HOST_ARR[$i]}" "tail -30 $DIR/n$i.log" >&2; exit 1; }
done
echo "peer mesh ready"

echo "== overlay pings"
for i in $(seq 1 $((N - 1))); do
  for j in $(seq 1 $((N - 1))); do
    [[ "$i" == "$j" ]] && continue
    target="10.66.0.$j"
    ok=0
    for _ in $(seq 1 20); do
      if sshh "${HOST_ARR[$i]}" "ping -c 2 -W 3 $target >/dev/null 2>&1"; then ok=1; break; fi
      sleep 1
    done
    if [[ "$ok" != 1 ]]; then
      echo "FAIL: ping n$i -> $target" >&2
      sshh "${HOST_ARR[$i]}" "tail -30 $DIR/n$i.log" >&2
      exit 1
    fi
  done
done
echo "all pairs ping"

echo "== restarting n1 keeps its address"
sshh "${HOST_ARR[1]}" "pkill -f '[s]tellaris-agent --config $DIR/n1.toml' 2>/dev/null" || true
sleep 2
sshn "${HOST_ARR[1]}" "{ setsid $BIN --config $DIR/n1.toml; } >$DIR/n1b.log 2>&1 </dev/null & exit 0" || true
for _ in $(seq 1 60); do sshq "${HOST_ARR[1]}" "curl -fsS --max-time 2 -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:$((API_BASE + 1))/v1/status" >/dev/null 2>&1 && break; sleep 0.5; done
addr=$(api 1 $((API_BASE + 1)) /v1/status | python3 -c 'import json,sys;d=json.load(sys.stdin);c=d.get("credential") or {};print(c.get("overlay_ip") or "")')
[[ "$addr" == "10.66.0.1" ]] || { echo "FAIL: restarted n1 has $addr" >&2; exit 1; }
echo "n1 kept 10.66.0.1"

echo "== hot reassign n1 to 10.66.0.9"
code=$(sshh "${HOST_ARR[0]}" "curl -s -o /tmp/reassign.out -w '%{http_code}' --max-time 5 -H 'x-stellaris-secret: $ADMIN' -H 'content-type: application/json' -d '{\"ip\":\"10.66.0.9\"}' http://127.0.0.1:$CTRL_PORT/v1/ipam/leases/${NODE_IDS[0]}/reassign")
[[ "$code" == "200" ]] || { echo "FAIL: reassign returned $code" >&2; sshh "${HOST_ARR[0]}" "cat /tmp/reassign.out" >&2; exit 1; }
for _ in $(seq 1 80); do
  addr=$(api 1 $((API_BASE + 1)) /v1/status | python3 -c 'import json,sys;d=json.load(sys.stdin);c=d.get("credential") or {};print(c.get("overlay_ip") or "")')
  [[ "$addr" == "10.66.0.9" ]] && break
  sleep 0.5
done
[[ "$addr" == "10.66.0.9" ]] || { echo "FAIL: n1 credential did not move to .9 (got $addr)" >&2; exit 1; }
for _ in $(seq 1 80); do
  sshh "${HOST_ARR[1]}" "ip -4 addr show stellaris0 2>/dev/null | grep -q '10.66.0.9'" && break
  sleep 0.5
done
sshh "${HOST_ARR[1]}" "ip -4 addr show stellaris0 | grep -q '10.66.0.9'" || {
  echo "FAIL: n1 TUN did not move to 10.66.0.9" >&2; sshh "${HOST_ARR[1]}" "ip -4 addr show stellaris0" >&2; exit 1; }
# The old address is released into quarantine and must no longer answer.
ok=0
for _ in $(seq 1 40); do
  if sshh "${HOST_ARR[2]}" "ping -c 2 -W 2 10.66.0.9 >/dev/null 2>&1"; then ok=1; break; fi
  sleep 1
done
[[ "$ok" == 1 ]] || { echo "FAIL: n2 cannot ping n1's new address .9" >&2; exit 1; }
if sshh "${HOST_ARR[2]}" "ping -c 2 -W 2 10.66.0.1 >/dev/null 2>&1"; then
  echo "FAIL: old address 10.66.0.1 still answers after reassign" >&2; exit 1
fi
LEASES=$(sshh "${HOST_ARR[0]}" "curl -fsS -H 'x-stellaris-secret: $ADMIN' http://127.0.0.1:$CTRL_PORT/v1/ipam/leases")
echo "$LEASES" | python3 -c "import json,sys; d=json.load(sys.stdin); assert any(q['ip']=='10.66.0.9' for q in d['leases']), d; assert any(q['ip']=='10.66.0.1' for q in d.get('quarantine',[])), d" || {
  echo "FAIL: lease/quarantine state wrong after reassign" >&2; echo "$LEASES" >&2; exit 1; }
echo "n1 hot-reassigned .1 -> .9 (old address quarantined)"

echo "== revoking the last member releases its lease"
LAST=$((N - 1))
REVOKED_IP="10.66.0.$LAST"
code=$(sshh "${HOST_ARR[0]}" "curl -s -o /tmp/revoke.out -w '%{http_code}' --max-time 5 -H 'x-stellaris-secret: $ADMIN' -H 'content-type: application/json' -d '{\"node_id\":\"${NODE_IDS[$((LAST - 1))]}\"}' http://127.0.0.1:$CTRL_PORT/v1/revoke")
[[ "$code" == "200" ]] || { echo "FAIL: revoke returned $code" >&2; sshh "${HOST_ARR[0]}" "cat /tmp/revoke.out" >&2; exit 1; }
sleep 2
LEASES=$(sshh "${HOST_ARR[0]}" "curl -fsS -H 'x-stellaris-secret: $ADMIN' http://127.0.0.1:$CTRL_PORT/v1/ipam/leases")
COUNT=$(echo "$LEASES" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["leases"]))')
[[ "$COUNT" == "$((N - 2))" ]] || { echo "FAIL: lease not released (count=$COUNT)" >&2; echo "$LEASES" >&2; exit 1; }
echo "$LEASES" | python3 -c "import json,sys; d=json.load(sys.stdin); ips=[q['ip'] for q in d.get('quarantine',[])]; assert '$REVOKED_IP' in ips, ips" || {
  echo "FAIL: $REVOKED_IP not quarantined" >&2; echo "$LEASES" >&2; exit 1; }
# Remaining members still ping each other.
for i in $(seq 1 $((LAST - 1))); do
  for j in $(seq 1 $((LAST - 1))); do
    [[ "$i" == "$j" ]] && continue
    sshh "${HOST_ARR[$i]}" "ping -c 2 -W 3 10.66.0.$j >/dev/null 2>&1" || {
      echo "FAIL: ping n$i -> n$j after revoke" >&2; exit 1; }
  done
done
echo "remaining members still ping"

echo "OK: IPAM auto-allocation, credentials, TUN addresses, restart, revoke+quarantine"
