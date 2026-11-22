#!/usr/bin/env bash
set -euo pipefail
# Requires root + Linux binary. Two isolated namespaces discover each other
# over UDP broadcast, then authenticate with PSK.
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing Linux binary: $BIN" >&2; exit 1; }
DIR=/tmp/stellaris-disc; rm -rf "$DIR"; mkdir -p "$DIR"/{a,b}-state
cleanup(){ kill ${A_PID:-} ${B_PID:-} 2>/dev/null || true; for ns in da db; do ip netns del $ns 2>/dev/null || true; done; if [[ "${KEEP:-0}" != 1 ]]; then rm -rf "$DIR"; fi; }
trap cleanup EXIT
for ns in da db; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip netns exec $ns ip link set lo up; done
ip link add va type veth peer name vb; ip link set va netns da; ip link set vb netns db
ip netns exec da ip addr add 10.203.0.1/24 dev va
ip netns exec db ip addr add 10.203.0.2/24 dev vb
ip netns exec da ip link set va up; ip netns exec db ip link set vb up
for n in a b; do
  ip=10.204.0.$([ $n = a ] && echo 1 || echo 2)
  under=10.203.0.$([ $n = a ] && echo 1 || echo 2)
  port=$([ $n = a ] && echo 46331 || echo 46332)
  api=$([ $n = a ] && echo 46341 || echo 46342)
  cat > "$DIR/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$DIR/$n-state"
overlay_ip = "$ip"
[network]
name = "discovery"
cidr = "10.204.0.0/16"
[network.auth]
mode = "psk"
secret = "discovery-secret"
[transport]
relay_urls = []
disable_relay = true
listen_port = $port
advertise = ["$under:$port"]
discovery_port = 47000
discovery_broadcast = "10.203.0.255:47000"
[api]
bind = "127.0.0.1:$api"
TOML
done
ip netns exec da "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec db "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
sleep 8
if ! grep -q 'discovered peer via UDP' "$DIR/a.log"; then
  echo "FAIL: no UDP-discovered peer" >&2
  tail -20 "$DIR/a.log" >&2
  tail -20 "$DIR/b.log" >&2
  exit 1
fi
if ! grep -q 'outbound iroh connected' "$DIR/a.log" && ! grep -q 'inbound iroh connection' "$DIR/a.log"; then
  echo "FAIL: discovered peer not connected" >&2
  tail -20 "$DIR/a.log" >&2
  exit 1
fi
echo "OK: UDP broadcast discovery + PSK works."
