#!/usr/bin/env bash
set -euo pipefail
# Two isolated Linux namespaces; mDNS/DNS-SD should discover the peer and connect.
# Dev-only unauthenticated mode: controller membership is not exercised here.
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing Linux binary: $BIN" >&2; exit 1; }
DIR="${DIR:-/tmp/stellaris-mdns}"; rm -rf "$DIR"; mkdir -p "$DIR"/{a,b}-state
cleanup(){ kill ${A_PID:-} ${B_PID:-} 2>/dev/null || true; for ns in ma mb; do ip netns del $ns 2>/dev/null || true; done; if [[ "${KEEP:-0}" != 1 ]]; then rm -rf "$DIR"; fi; }
trap cleanup EXIT
for ns in ma mb; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip netns exec $ns ip link set lo up; done
ip link add va type veth peer name vb; ip link set va netns ma; ip link set vb netns mb
ip netns exec ma ip addr add 10.205.0.1/24 dev va
ip netns exec mb ip addr add 10.205.0.2/24 dev vb
ip netns exec ma ip link set va up; ip netns exec mb ip link set vb up
for n in a b; do
  ip=10.206.0.$([ $n = a ] && echo 1 || echo 2)
  under=10.205.0.$([ $n = a ] && echo 1 || echo 2)
  port=$([ $n = a ] && echo 46531 || echo 46532)
  api=$([ $n = a ] && echo 46541 || echo 46542)
  cat > "$DIR/$n.toml" <<TOML
[node]
name = "$n"
state_dir = "$DIR/$n-state"
overlay_ip = "$ip"
[network]
name = "mdns"
cidr = "10.206.0.0/16"
[transport]
relay_urls = []
disable_relay = true
listen_port = $port
bind_ip = "$under"
advertise = ["$under:$port"]
mdns = true
allow_unauthenticated_discovery = true
[api]
bind = "127.0.0.1:$api"
TOML
done
ip netns exec ma "$BIN" --config "$DIR/a.toml" > "$DIR/a.log" 2>&1 & A_PID=$!
ip netns exec mb "$BIN" --config "$DIR/b.toml" > "$DIR/b.log" 2>&1 & B_PID=$!
sleep 8
if ! grep -q 'discovered peer via mDNS' "$DIR/a.log"; then
  echo "FAIL: A did not discover peer via mDNS" >&2
  tail -30 "$DIR/a.log" >&2; tail -30 "$DIR/b.log" >&2; exit 1
fi
if ! grep -q 'outbound iroh connected\|inbound iroh connection' "$DIR/a.log"; then
  echo "FAIL: mDNS peer not connected" >&2
  tail -30 "$DIR/a.log" >&2; exit 1
fi
echo "OK: mDNS discovery works in dev-only unauthenticated mode."
