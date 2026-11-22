#!/usr/bin/env bash
set -euo pipefail
# Two Linux containers on one Docker bridge: mDNS must discover the peer and
# PSK auth must complete. Intended for a Linux Docker host.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/release/stellaris-agent}"
IMAGE="${IMAGE:-nginx:latest}"
[[ -x "$BIN" ]] || { echo "missing binary: $BIN" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/stellaris-docker-mdns.XXXXXX")"
NET="stellaris-mdns-$$"
cleanup(){ docker rm -f mdns-a mdns-b >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
IFACE="${MDNS_INTERFACE:-}"
IFACE_LINE=""
[[ -n "$IFACE" ]] && IFACE_LINE="mdns_interface=\"$IFACE\""
export IFACE_LINE
mkdir -p "$TMP"/{a-state,b-state}
cat > "$TMP/a.toml" <<TOML
[node]
name="a"
state_dir="/state"
overlay_ip="10.209.0.1"
[network]
name="docker-mdns"
cidr="10.209.0.0/16"
[network.auth]
mode="psk"
secret="docker-mdns-secret"
[transport]
relay_urls=[]
disable_relay=true
listen_port=46831
bind_ip="172.31.0.2"
advertise=["172.31.0.2:46831"]
mdns=true
${IFACE_LINE}
[api]
bind="127.0.0.1:46841"
TOML
cat > "$TMP/b.toml" <<TOML
[node]
name="b"
state_dir="/state"
overlay_ip="10.209.0.2"
[network]
name="docker-mdns"
cidr="10.209.0.0/16"
[network.auth]
mode="psk"
secret="docker-mdns-secret"
[transport]
relay_urls=[]
disable_relay=true
listen_port=46832
bind_ip="172.31.0.3"
advertise=["172.31.0.3:46832"]
mdns=true
${IFACE_LINE}
[api]
bind="127.0.0.1:46842"
TOML
docker network create --subnet 172.31.0.0/24 "$NET" >/dev/null
docker run -d --name mdns-a --network "$NET" --ip 172.31.0.2 \
  -v "$BIN:/stellaris-agent:ro" -v "$TMP/a.toml:/config.toml:ro" -v "$TMP/a-state:/state" "$IMAGE" \
  /stellaris-agent --config /config.toml >/dev/null
docker run -d --name mdns-b --network "$NET" --ip 172.31.0.3 \
  -v "$BIN:/stellaris-agent:ro" -v "$TMP/b.toml:/config.toml:ro" -v "$TMP/b-state:/state" "$IMAGE" \
  /stellaris-agent --config /config.toml >/dev/null
sleep 8
A_LOG="$(docker logs mdns-a 2>&1 || true)"
B_LOG="$(docker logs mdns-b 2>&1 || true)"
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
echo "OK: container mDNS discovery + PSK works."
