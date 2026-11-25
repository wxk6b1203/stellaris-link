#!/usr/bin/env bash
set -euo pipefail
# Two Docker macvlan containers get real LAN IPs on one L2 segment.
# This validates mDNS across the physical LAN without a second Linux host.
#
# Required:
#   PARENT=enp1s0 SUBNET=10.0.10.0/23 GATEWAY=10.0.10.1 \
#   IP_A=10.0.10.240 IP_B=10.0.10.242 ./scripts/test-docker-mdns-macvlan.sh
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/release/stellaris-agent}"
IMAGE="${IMAGE:-nginx:latest}"
: "${PARENT:?set PARENT to the host LAN interface}"
: "${SUBNET:?set SUBNET (e.g. 10.0.10.0/23)}"
: "${GATEWAY:?set GATEWAY}"
: "${IP_A:?set IP_A}"
: "${IP_B:?set IP_B}"
[[ -x "$BIN" ]] || { echo "missing binary: $BIN" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-macvlan.XXXXXX")"
NET="stellaris-mcv-$$"
cleanup(){ docker rm -f mcv-a mcv-b >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
mkdir -p "$TMP"/{a-state,b-state}
cat > "$TMP/a.toml" <<TOML
[node]
name="a"
state_dir="/state"
overlay_ip="10.214.0.1"
[network]
name="macvlan-mdns"
cidr="10.214.0.0/16"
[transport]
relay_urls=[]
disable_relay=true
listen_port=46851
bind_ip="$IP_A"
advertise=["$IP_A:46851"]
mdns=true
mdns_interface="eth0"
allow_unauthenticated_discovery=true
[api]
bind="127.0.0.1:46861"
TOML
cat > "$TMP/b.toml" <<TOML
[node]
name="b"
state_dir="/state"
overlay_ip="10.214.0.2"
[network]
name="macvlan-mdns"
cidr="10.214.0.0/16"
[transport]
relay_urls=[]
disable_relay=true
listen_port=46852
bind_ip="$IP_B"
advertise=["$IP_B:46852"]
mdns=true
mdns_interface="eth0"
allow_unauthenticated_discovery=true
[api]
bind="127.0.0.1:46862"
TOML
docker network create -d macvlan --subnet="$SUBNET" --gateway="$GATEWAY" -o parent="$PARENT" "$NET" >/dev/null
docker run -d --name mcv-a --network "$NET" --ip "$IP_A" \
  -v "$BIN:/stellaris-agent:ro" -v "$TMP/a.toml:/config.toml:ro" -v "$TMP/a-state:/state" "$IMAGE" \
  /stellaris-agent --config /config.toml >/dev/null
docker run -d --name mcv-b --network "$NET" --ip "$IP_B" \
  -v "$BIN:/stellaris-agent:ro" -v "$TMP/b.toml:/config.toml:ro" -v "$TMP/b-state:/state" "$IMAGE" \
  /stellaris-agent --config /config.toml >/dev/null
sleep 8
A_LOG="$(docker logs mcv-a 2>&1 || true)"
B_LOG="$(docker logs mcv-b 2>&1 || true)"
if ! grep -q 'discovered peer via mDNS' <<<"$A_LOG"; then
  echo "FAIL: A did not discover via mDNS" >&2; echo "$A_LOG" >&2; exit 1
fi
if ! grep -q 'discovered peer via mDNS' <<<"$B_LOG"; then
  echo "FAIL: B did not discover via mDNS" >&2; echo "$B_LOG" >&2; exit 1
fi
if ! grep -q 'outbound iroh connected\|inbound iroh connection' <<<"$A_LOG"; then
  echo "FAIL: A did not connect" >&2; echo "$A_LOG" >&2; exit 1
fi
if ! grep -q 'outbound iroh connected\|inbound iroh connection' <<<"$B_LOG"; then
  echo "FAIL: B did not connect" >&2; echo "$B_LOG" >&2; exit 1
fi
echo "OK: macvlan mDNS discovery works on a real LAN in dev-only unauthenticated mode."
