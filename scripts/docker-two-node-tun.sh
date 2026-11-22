#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/.docker-demo"
NET=stellaris-test
TARGET_VOL=stellaris-target
CARGO_VOL=stellaris-cargo
RUNTIME_IMAGE=stellaris-runtime:test
RUST_IMAGE=rust:1.99-bookworm

cleanup() {
  docker rm -f stellaris-a stellaris-b >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1; then
  echo "building runtime image..."
  docker build -f "$ROOT/docker/runtime.Dockerfile" -t "$RUNTIME_IMAGE" "$ROOT"
fi

if ! docker run --rm -v "$TARGET_VOL":/target "$RUNTIME_IMAGE" test -x /target/debug/stellaris-agent; then
  echo "building linux binaries in docker (first run may take a few minutes)..."
  docker run --rm -v "$ROOT":/work -w /work \
    -v "$CARGO_VOL":/usr/local/cargo/registry -v "$TARGET_VOL":/target \
    -e CARGO_TARGET_DIR=/target "$RUST_IMAGE" \
    cargo build -p stellaris-agent -p stellaris-cli
fi

rm -rf "$DEMO"
mkdir -p "$DEMO/a-state" "$DEMO/b-state"

for n in a b; do
  api=$([ "$n" = a ] && echo 7781 || echo 7782)
  ip=$([ "$n" = a ] && echo 10.7.0.1 || echo 10.7.0.2)
  port=$([ "$n" = a ] && echo 41001 || echo 41002)
  cat > "$DEMO/$n.toml" <<TOML
[node]
name = "docker-$n"
state_dir = "/state"
overlay_ip = "$ip"

[network]
name = "docker-demo"
cidr = "10.7.0.0/16"

[transport]
relay_urls = []
disable_relay = true
listen_port = $port

[routing]
rib_mode = "full"
max_routes = 10000
ecmp_max = 8

[dataplane]
enabled = true
tun_name = "stellaris0"
mtu = 1280

[api]
bind = "127.0.0.1:$api"
TOML
done

A_ID=$(docker run --rm -v "$DEMO/a.toml":/cfg/a.toml:ro -v "$DEMO/a-state":/state -v "$TARGET_VOL":/target "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/a.toml --print-id)
B_ID=$(docker run --rm -v "$DEMO/b.toml":/cfg/b.toml:ro -v "$DEMO/b-state":/state -v "$TARGET_VOL":/target "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/b.toml --print-id)
echo "node A: $A_ID"
echo "node B: $B_ID"

cat >> "$DEMO/a.toml" <<TOML

[[peers]]
name = "docker-b"
endpoint_id = "$B_ID"
overlay_ip = "10.7.0.2"
addrs = ["172.28.0.3:41002"]
TOML
cat >> "$DEMO/b.toml" <<TOML

[[peers]]
name = "docker-a"
endpoint_id = "$A_ID"
overlay_ip = "10.7.0.1"
addrs = ["172.28.0.2:41001"]
TOML

sync
sleep 1
docker rm -f stellaris-a stellaris-b >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet 172.28.0.0/24 "$NET" >/dev/null
docker run -d --name stellaris-a --privileged --network "$NET" --ip 172.28.0.2 \
  -v "$DEMO/a.toml":/cfg/a.toml:ro -v "$DEMO/a-state":/state -v "$TARGET_VOL":/target \
  "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/a.toml >/dev/null
docker run -d --name stellaris-b --privileged --network "$NET" --ip 172.28.0.3 \
  -v "$DEMO/b.toml":/cfg/b.toml:ro -v "$DEMO/b-state":/state -v "$TARGET_VOL":/target \
  "$RUNTIME_IMAGE" /target/debug/stellaris-agent --config /cfg/b.toml >/dev/null

for _ in $(seq 1 60); do
  if docker exec stellaris-a /target/debug/stellaris --api http://127.0.0.1:7781 status >/dev/null 2>&1 \
     && docker exec stellaris-b /target/debug/stellaris --api http://127.0.0.1:7782 status >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "--- A status ---"
docker exec stellaris-a /target/debug/stellaris --api http://127.0.0.1:7781 status
echo "--- A peers ---"
docker exec stellaris-a /target/debug/stellaris --api http://127.0.0.1:7781 peer list
echo "--- A TUN ---"
docker exec stellaris-a ip -4 addr show stellaris0
echo "--- ping A -> B (1000 bytes) ---"
docker exec stellaris-a ping -4 -c 3 -s 1000 -W 2 10.7.0.2
echo "--- ping B -> A ---"
docker exec stellaris-b ping -4 -c 3 -W 2 10.7.0.1

echo
echo "OK: two-node TUN overlay is up. Containers will be removed on exit."
