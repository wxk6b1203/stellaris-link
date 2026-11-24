#!/usr/bin/env bash
# Route-safety regression: default routes are opt-in, foreign routes are not
# overwritten, and installed routes carry the private proto tag.
# Requires root, iproute2 and TUN.
set -euo pipefail
BIN="${BIN:-$(pwd)/target/release/stellaris-agent}"
[[ -x "$BIN" ]] || { echo "missing Linux binary: $BIN" >&2; exit 1; }
NS=stellaris-route-safety
DIR="${DIR:-/tmp/stellaris-route-safety}"
rm -rf "$DIR"; mkdir -p "$DIR"
cleanup(){
  kill "${PID:-}" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  rm -rf "$DIR"
}
trap cleanup EXIT
ip netns del "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
# A foreign route we must not touch.
ip netns exec "$NS" ip link add dummy0 type dummy
ip netns exec "$NS" ip addr add 192.168.99.1/24 dev dummy0
ip netns exec "$NS" ip link set dummy0 up

NODE_B="0303030303030303030303030303030303030303030303030303030303030303"
cat > "$DIR/agent.toml" <<TOML
[node]
name = "route-safety"
state_dir = "$DIR/state"
overlay_ip = "10.251.0.1"
[network]
name = "route-safety"
cidr = "10.251.0.0/16"
[transport]
disable_relay = true
listen_port = 46401
[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
[api]
bind = "127.0.0.1:46402"
[[peers]]
name = "b"
endpoint_id = "$NODE_B"
overlay_ip = "10.251.0.2"
[[routes]]
prefix = "0.0.0.0/0"
via = "b"
[[routes]]
prefix = "192.168.99.0/24"
via = "b"
TOML

ip netns exec "$NS" env RUST_LOG=info "$BIN" --config "$DIR/agent.toml" >"$DIR/agent.log" 2>&1 &
PID=$!
sleep 4
# Default route must not be installed.
if ip netns exec "$NS" ip route show default | grep -q "dev stellaris0"; then
  echo "FAIL: default route installed without allow_default_route" >&2
  ip netns exec "$NS" ip route show >&2
  exit 1
fi
# The foreign route must still point at dummy0, not at the TUN.
if ip netns exec "$NS" ip route show 192.168.99.0/24 | grep -q "dev stellaris0"; then
  echo "FAIL: foreign route was replaced" >&2
  ip netns exec "$NS" ip route show 192.168.99.0/24 >&2
  exit 1
fi
grep -q "refusing to install a default route" "$DIR/agent.log" || {
  echo "FAIL: no default-route refusal log" >&2; tail -20 "$DIR/agent.log" >&2; exit 1; }
grep -q "OS route conflict" "$DIR/agent.log" || {
  echo "FAIL: no conflict log" >&2; tail -20 "$DIR/agent.log" >&2; exit 1; }
echo "default route refused and foreign route preserved"

kill -9 "$PID" 2>/dev/null || true
sleep 1
# Opt in to default routes and conflict replacement.
sed -i 's/^mtu = 1280$/mtu = 1280\nallow_default_route = true\nreplace_existing_routes = true/' "$DIR/agent.toml"
ip netns exec "$NS" env RUST_LOG=info "$BIN" --config "$DIR/agent.toml" >"$DIR/agent2.log" 2>&1 &
PID=$!
sleep 4
if ! ip netns exec "$NS" ip route show default | grep -q "dev stellaris0"; then
  echo "FAIL: default route not installed after allow_default_route" >&2
  ip netns exec "$NS" ip route show >&2
  exit 1
fi
ip netns exec "$NS" ip route show | grep -q "proto 240" || {
  echo "FAIL: installed route lost the ownership tag" >&2
  ip netns exec "$NS" ip route show >&2
  exit 1
}
ip netns exec "$NS" ip route show 192.168.99.0/24 | grep -q "dev stellaris0" || {
  echo "FAIL: explicit replace did not take over the route" >&2
  ip netns exec "$NS" ip route show 192.168.99.0/24 >&2
  exit 1
}
echo "OK: route safety (opt-in default, conflict skip/replace, proto tag) verified"
