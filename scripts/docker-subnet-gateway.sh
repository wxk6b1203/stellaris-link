#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/.docker-gw"
UNDERLAY=stellaris-gw-underlay
LAN=stellaris-gw-lan
TARGET_VOL=stellaris-target
CARGO_VOL=stellaris-cargo
RUNTIME_IMAGE=stellaris-runtime:test
RUST_IMAGE=rust:1.99-bookworm

cleanup() {
  docker rm -f gw-a gw-b gw-c >/dev/null 2>&1 || true
  docker network rm "$UNDERLAY" "$LAN" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1; then
  docker build -f "$ROOT/docker/runtime.Dockerfile" -t "$RUNTIME_IMAGE" "$ROOT"
fi
if ! docker run --rm -v "$TARGET_VOL":/target "$RUNTIME_IMAGE" test -x /target/debug/stellaris-agent; then
  docker run --rm -v "$ROOT":/work -w /work \
    -v "$CARGO_VOL":/usr/local/cargo/registry -v "$TARGET_VOL":/target \
    -e CARGO_TARGET_DIR=/target "$RUST_IMAGE" \
    cargo build -p stellaris-agent -p stellaris-cli
fi

rm -rf "$DEMO"
mkdir -p "$DEMO/a-state" "$DEMO/b-state"
NAT_TOML=false
if [[ "${NAT:-0}" == "1" ]]; then NAT_TOML=true; fi

cat > "$DEMO/a.toml" <<'TOML'
[node]
name = "gw-a"
state_dir = "/state"
overlay_ip = "10.77.0.1"
zone = "az-a"

[network]
name = "docker-gw"
cidr = "10.77.0.0/16"

[transport]
relay_urls = []
disable_relay = true
listen_port = 41101

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:7791"
TOML
cat > "$DEMO/b.toml" <<TOML
[node]
name = "gw-b"
state_dir = "/state"
overlay_ip = "10.77.0.2"
zone = "az-b"

[network]
name = "docker-gw"
cidr = "10.77.0.0/16"

[transport]
relay_urls = []
disable_relay = true
listen_port = 41102

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280
advertise = ["192.168.50.0/24"]
nat = $NAT_TOML

[api]
bind = "127.0.0.1:7792"
TOML

A_ID=$(docker run --rm -v "$DEMO/a.toml":/cfg/a.toml:ro -v "$DEMO/a-state":/state -v "$TARGET_VOL":/target "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/a.toml --print-id)
B_ID=$(docker run --rm -v "$DEMO/b.toml":/cfg/b.toml:ro -v "$DEMO/b-state":/state -v "$TARGET_VOL":/target "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/b.toml --print-id)

cat >> "$DEMO/a.toml" <<TOML

[[peers]]
name = "gw-b"
endpoint_id = "$B_ID"
overlay_ip = "10.77.0.2"
advertised = ["192.168.50.0/24"]
addrs = ["172.29.0.3:41102"]

[[routes]]
prefix = "192.168.50.0/24"
via = "gw-b"
TOML
cat >> "$DEMO/b.toml" <<TOML

[[peers]]
name = "gw-a"
endpoint_id = "$A_ID"
overlay_ip = "10.77.0.1"
addrs = ["172.29.0.2:41101"]
TOML

sync
sleep 1
docker rm -f gw-a gw-b gw-c >/dev/null 2>&1 || true
docker network rm "$UNDERLAY" "$LAN" >/dev/null 2>&1 || true
docker network create --subnet 172.29.0.0/24 "$UNDERLAY" >/dev/null
docker network create --subnet 192.168.50.0/24 "$LAN" >/dev/null

docker run -d --name gw-a --privileged --network "$UNDERLAY" --ip 172.29.0.2 \
  -v "$DEMO/a.toml":/cfg/a.toml:ro -v "$DEMO/a-state":/state -v "$TARGET_VOL":/target \
  "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/a.toml >/dev/null
docker run -d --name gw-b --privileged --network "$UNDERLAY" --ip 172.29.0.3 \
  -v "$DEMO/b.toml":/cfg/b.toml:ro -v "$DEMO/b-state":/state -v "$TARGET_VOL":/target \
  "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/b.toml >/dev/null
docker run -d --name gw-c --cap-add NET_ADMIN --network "$LAN" --ip 192.168.50.3 \
  "$RUNTIME_IMAGE" sleep infinity >/dev/null
docker network connect --ip 192.168.50.2 "$LAN" gw-b

# c is a plain host: no agent. With NAT=1 it only needs a default route;
# otherwise it needs an explicit return route to the overlay via b.
docker exec gw-c ip route replace default via 192.168.50.2
if [[ "${NAT:-0}" != "1" ]]; then
  docker exec gw-c ip route add 10.77.0.0/16 via 192.168.50.2
fi
# b forwards between TUN/eth0/eth1; Docker's FORWARD policy is DROP by default.
docker exec gw-b iptables -P FORWARD ACCEPT

for _ in $(seq 1 60); do
  if docker exec gw-a /target/debug/stellaris --api http://127.0.0.1:7791 status >/dev/null 2>&1 \
     && docker exec gw-b /target/debug/stellaris --api http://127.0.0.1:7792 status >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
# The reconciler is event-driven; one second is enough after the snapshot.
sleep 2

echo "--- A peers ---"
docker exec gw-a /target/debug/stellaris --api http://127.0.0.1:7791 peer list
echo "--- A OS routes ---"
docker exec gw-a ip route
echo "--- A FIB ---"
docker exec gw-a /target/debug/stellaris --api http://127.0.0.1:7791 route list --view fib
echo "--- ping A -> C (C has no agent) ---"
docker exec gw-a ping -4 -c 3 -W 2 192.168.50.3
echo "--- ping A -> C, 1000 bytes ---"
docker exec gw-a ping -4 -c 3 -s 1000 -W 2 192.168.50.3

echo
echo "OK: a -> b -> c subnet gateway works; c has no agent."
