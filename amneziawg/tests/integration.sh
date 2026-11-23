#!/bin/bash
# Container netns test: real dig must fill the nft set, unrelated names must not,
# DNS must still answer after the sniffer is paused, and a saved cache must
# come back without a new lookup.
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

jq -n --arg k "$priv" --arg p "$pub" '{
  awg_conf: "",
  private_key: $k,
  peer_public_key: $p,
  address: "10.8.0.2/32",
  endpoint: "203.0.113.10:51820",
  jc: 4, jmin: 40, jmax: 70, s1: 0, s2: 0,
  h1: "1", h2: "2", h3: "3", h4: "4",
  keepalive: 25, mtu: 1280,
  domains: ["example.com", "wikimedia.org"],
  cidrs: ["203.0.113.0/24"],
  exclude_cidrs: ["192.168.2.0/24"],
  strict: true,
  warmup: false,
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
  if sudo docker logs "$name" 2>&1 | grep -q 'watching DNS responses'; then
    ready=1
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

echo '--- listed name ---'
mapfile -t example_ips < <(sudo docker exec "$name" dig +time=3 +tries=1 example.com A +short | grep -E '^[0-9.]+$' || true)
[[ ${#example_ips[@]} -gt 0 ]]
for _ in $(seq 1 20); do
  if sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q "${example_ips[0]}"; then
    break
  fi
  sleep 0.5
done
sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q "${example_ips[0]}"

echo '--- subdomain and CNAME ---'
mapfile -t wiki_ips < <(sudo docker exec "$name" dig +time=3 +tries=1 www.wikipedia.org A +short | grep -E '^[0-9.]+$' || true)
[[ ${#wiki_ips[@]} -gt 0 ]]
for _ in $(seq 1 20); do
  if sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q "${wiki_ips[0]}"; then
    break
  fi
  sleep 0.5
done
sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q "${wiki_ips[0]}"

echo '--- not listed ---'
mapfile -t other_ips < <(sudo docker exec "$name" dig +time=3 +tries=1 one.one.one.one A +short | grep -E '^[0-9.]+$' || true)
[[ ${#other_ips[@]} -gt 0 ]]
sleep 1
set_dump=$(sudo docker exec "$name" nft list set inet awg_pbr routed_v4)
for ip in "${other_ips[@]}"; do
  if grep -q "$ip" <<<"$set_dump"; then
    echo "unlisted address $ip entered the set" >&2
    exit 1
  fi
done

echo '--- tcp response ---'
mapfile -t tcp_ips < <(sudo docker exec "$name" dig +tcp +time=3 +tries=1 example.com A +short | grep -E '^[0-9.]+$' || true)
[[ ${#tcp_ips[@]} -gt 0 ]]

echo '--- strict route and health ---'
sudo docker exec "$name" ip route show table 51820 | grep -q blackhole
sudo docker exec "$name" ip rule show | grep -q 'fwmark 0x77'
sudo docker exec "$name" nft list chain inet awg_pbr v6out | grep -q routed_v6
sudo docker exec "$name" curl -fsS http://127.0.0.1:10799/cgi-bin/health | grep -q ok

echo '--- cache persisted ---'
for _ in $(seq 1 20); do
  if sudo docker exec "$name" grep -q "${example_ips[0]}" /data/learned.json; then
    break
  fi
  sleep 0.5
done
sudo docker exec "$name" grep -q "${example_ips[0]}" /data/learned.json

echo '--- restore after sniffer restart ---'
sudo docker exec "$name" nft delete element inet awg_pbr routed_v4 "{ ${example_ips[0]} }"
sudo docker exec "$name" sh -c 'kill -TERM "$(pidof dns-snoop)"'
for _ in $(seq 1 30); do
  if sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q "${example_ips[0]}"; then
    break
  fi
  sleep 0.5
done
sudo docker exec "$name" nft list set inet awg_pbr routed_v4 | grep -q "${example_ips[0]}"

echo '--- dns fail-open ---'
sudo docker exec "$name" sh -c 'kill -STOP "$(pidof dns-snoop)"'
sudo docker exec "$name" dig +time=3 +tries=1 example.com A +short | grep -q .
sudo docker exec "$name" sh -c 'kill -CONT "$(pidof dns-snoop)"' || true

echo INTEGRATION_OK
