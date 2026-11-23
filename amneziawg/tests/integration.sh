#!/bin/bash
# Runs the built image in its own network namespace (not the host's) and checks
# DNS-driven nftables, strict-mode blackhole, and cleanup.
set -euo pipefail
IMG=${1:-awg-addon:amd64}
name=awg-it-$$
workdir=$(mktemp -d)
cleanup() {
  sudo docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
trap cleanup EXIT

priv=$(sudo docker run --rm --entrypoint /usr/bin/awg "$IMG" genkey | tr -d '\r')
pub=$(printf '%s\n' "$priv" | sudo docker run -i --rm --entrypoint /usr/bin/awg "$IMG" pubkey | tr -d '\r')
echo "amneziawg-go: $(sudo docker run --rm --entrypoint /usr/bin/amneziawg-go "$IMG" --version | head -n 1)"
echo "awg: $(sudo docker run --rm --entrypoint /usr/bin/awg "$IMG" --version)"

jq -n --arg k "$priv" --arg p "$pub" '{
  awg_conf: "",
  private_key: $k,
  peer_public_key: $p,
  address: "10.8.0.2/32",
  endpoint: "203.0.113.10:51820",
  jc: 4, jmin: 40, jmax: 70, s1: 0, s2: 0,
  h1: "1", h2: "2", h3: "3", h4: "4",
  keepalive: 25, mtu: 1280,
  domains: ["example.com"],
  cidrs: ["203.0.113.0/24"],
  exclude_cidrs: ["192.168.2.0/24"],
  strict: true,
  upstream_dns: ["1.1.1.1"],
  manage_dns: false,
  route_timeout: 86400,
  log_level: "info"
}' >"${workdir}/options.json"

sudo docker run -d --name "$name" \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v "${workdir}:/data" \
  "$IMG" >/dev/null

ready=0
for _ in $(seq 1 40); do
  if sudo docker logs "$name" 2>&1 | grep -q 'DNS resolver listening'; then
    ready=1
    break
  fi
  if sudo docker logs "$name" 2>&1 | grep -q 'service failed'; then
    break
  fi
  sleep 1
done
echo '--- logs ---'
sudo docker logs "$name" 2>&1
[[ $ready -eq 1 ]]

if sudo docker logs "$name" 2>&1 | grep -F "$priv" >/dev/null; then
  echo 'private key leaked into logs' >&2
  exit 1
fi

echo '--- A / AAAA ---'
sudo docker exec "$name" dig @127.0.0.1 example.com A +short
aaaa=$(sudo docker exec "$name" dig @127.0.0.1 example.com AAAA +short)
echo "AAAA=$aaaa"
[[ $aaaa == "100::1" ]]
sudo docker exec "$name" dig @127.0.0.1 www.example.com A +short >/dev/null

echo '--- nft set ---'
sudo docker exec "$name" nft list set inet awg_pbr routed_v4
sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q 'elements'

echo '--- strict route ---'
sudo docker exec "$name" ip route show table 51820 | grep -q blackhole
sudo docker exec "$name" ip rule show | grep -q 'fwmark 0x77'
sudo docker exec "$name" ip rule show | grep -q 'to 203.0.113.10'

echo '--- health ---'
sudo docker exec "$name" curl -fsS http://127.0.0.1:10799/cgi-bin/health

echo '--- awg ---'
sudo docker exec "$name" awg show awg0 | head -n 20

echo '--- cleanup ---'
sudo docker exec "$name" /usr/bin/awg-down
if sudo docker exec "$name" nft list table inet awg_pbr >/dev/null 2>&1; then
  echo 'nft table survived cleanup' >&2
  exit 1
fi
if sudo docker exec "$name" ip rule show | grep -q 'fwmark 0x77'; then
  echo 'fwmark rule survived cleanup' >&2
  exit 1
fi
echo INTEGRATION_OK
