#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
source "${ROOT}/rootfs/usr/lib/awg/lib.sh"

fails=0
ok() { printf 'ok %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails + 1)); }

key1=$(openssl rand -base64 32)
key2=$(openssl rand -base64 32)
key3=$(openssl rand -base64 32)

new_run() {
  AWG_RUN_DIR=$(mktemp -d)
  AWG_DNS_IP=127.0.0.1
  export AWG_RUN_DIR AWG_DNS_IP
}

prepare_json() {
  AWG_OPTIONS=$1
  export AWG_OPTIONS
  load_options
  prepare_config
}

if (
  new_run
  jq -n --arg k "$key1" --arg p "$key2" '{
    awg_conf: "",
    address: "10.8.0.2/32",
    jc: 0, jmin: 0, jmax: 0, s1: 0, s2: 0,
    h1: "", h2: "", h3: "", h4: "",
    private_key: $k, peer_public_key: $p,
    endpoint: "203.0.113.10:51820", keepalive: 25, mtu: 1280,
    domains: ["*.Example.COM.", "openapi.tuyaeu.com"],
    cidrs: ["203.0.113.0/24"],
    exclude_cidrs: ["192.168.2.0/24"],
    strict: true, upstream_dns: [], manage_dns: false,
    route_timeout: 86400, log_level: "info"
  }' >"${AWG_RUN_DIR}/options.json"
  prepare_json "${AWG_RUN_DIR}/options.json"
  if grep -q '^Jc = ' "${AWG_RUN_DIR}/awg0.conf"; then exit 1; fi
  grep -q 'PrivateKey = '"$key1" "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'Endpoint = 203.0.113.10:51820' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'AllowedIPs = 0.0.0.0/0' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'PersistentKeepalive = 25' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'nftset=/example.com/4#inet#awg_pbr#routed_v4' "${AWG_RUN_DIR}/dnsmasq.conf"
  grep -q 'address=/example.com/100::1' "${AWG_RUN_DIR}/dnsmasq.conf"
  grep -q 'nftset=/openapi.tuyaeu.com/4#inet#awg_pbr#routed_v4' "${AWG_RUN_DIR}/dnsmasq.conf"
  grep -q 'listen-address=127.0.0.1' "${AWG_RUN_DIR}/dnsmasq.conf"
  ! grep -q 'Table' "${AWG_RUN_DIR}/awg0.conf"
); then ok structured; else bad structured; fi

pasted=$(cat <<EOF
[Interface]
PrivateKey = ${key1}
Address = 10.9.0.2/32
DNS = 1.1.1.1
Table = auto
MTU = 1400
FwMark = 123
PostUp = echo owned
Jc = 4
Jmin = 40
Jmax = 70
I1 = <b 0x01> <r 4>

[Peer]
PublicKey = ${key2}
PresharedKey = ${key3}
Endpoint = 198.51.100.8:47000
AllowedIPs = 10.0.0.0/8
EOF
)

if (
  new_run
  jq -n --arg conf "$pasted" '{
    awg_conf: $conf,
    address: "", jc: 0, jmin: 0, jmax: 0, s1: 0, s2: 0,
    h1: "", h2: "", h3: "", h4: "",
    endpoint: "", keepalive: 25, mtu: 1280,
    domains: [], cidrs: [], exclude_cidrs: [],
    strict: false, upstream_dns: ["9.9.9.9"], manage_dns: false,
    route_timeout: 3600, log_level: "info"
  }' >"${AWG_RUN_DIR}/options.json"
  prepare_json "${AWG_RUN_DIR}/options.json"
  grep -q 'Jc = 4' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'I1 = <b 0x01> <r 4>' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'Endpoint = 198.51.100.8:47000' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'AllowedIPs = 0.0.0.0/0' "${AWG_RUN_DIR}/awg0.conf"
  grep -q 'PresharedKey = '"$key3" "${AWG_RUN_DIR}/awg0.conf"
  ! grep -q 'PostUp' "${AWG_RUN_DIR}/awg0.conf"
  ! grep -q 'DNS' "${AWG_RUN_DIR}/awg0.conf"
  ! grep -q 'Table' "${AWG_RUN_DIR}/awg0.conf"
  ! grep -q 'FwMark' "${AWG_RUN_DIR}/awg0.conf"
  ! grep -q 'Address' "${AWG_RUN_DIR}/awg0.conf"
  grep -q '^AWG_ADDRESS=10\.9\.0\.2/32' "${AWG_RUN_DIR}/runtime.env" || grep -q "AWG_ADDRESS=10.9.0.2/32" "${AWG_RUN_DIR}/runtime.env"
  grep -q '^AWG_MTU=1400' "${AWG_RUN_DIR}/runtime.env" || grep -q "AWG_MTU=1400" "${AWG_RUN_DIR}/runtime.env"
  grep -q 'server=9.9.9.9' "${AWG_RUN_DIR}/dnsmasq.conf"
); then ok pasted; else bad pasted; fi

expect_die() {
  local name=$1
  shift
  if (set -euo pipefail; "$@") >/tmp/awg-test-out 2>/tmp/awg-test-err; then
    bad "$name"
  else
    ok "$name"
  fi
}

expect_die default-cidr bash -c "
  source '${ROOT}/rootfs/usr/lib/awg/lib.sh'
  AWG_RUN_DIR=\$(mktemp -d)
  AWG_DNS_IP=127.0.0.1
  jq -n --arg k '$key1' --arg p '$key2' '{
    awg_conf:\"\", private_key:\$k, peer_public_key:\$p, address:\"10.8.0.2/32\",
    endpoint:\"203.0.113.10:51820\", jc:0,jmin:0,jmax:0,s1:0,s2:0,
    h1:\"\",h2:\"\",h3:\"\",h4:\"\", keepalive:25, mtu:1280,
    domains:[], cidrs:[\"0.0.0.0/0\"], exclude_cidrs:[], strict:true,
    upstream_dns:[], manage_dns:false, route_timeout:86400, log_level:\"info\"
  }' >\"\$AWG_RUN_DIR/options.json\"
  AWG_OPTIONS=\$AWG_RUN_DIR/options.json
  load_options
"

expect_die bad-domain bash -c "
  source '${ROOT}/rootfs/usr/lib/awg/lib.sh'
  AWG_RUN_DIR=\$(mktemp -d)
  jq -n '{
    awg_conf:\"\", address:\"\", endpoint:\"\", jc:0,jmin:0,jmax:0,s1:0,s2:0,
    h1:\"\",h2:\"\",h3:\"\",h4:\"\", keepalive:25, mtu:1280,
    domains:[\"not a domain\"], cidrs:[], exclude_cidrs:[], strict:true,
    upstream_dns:[], manage_dns:false, route_timeout:86400, log_level:\"info\"
  }' >\"\$AWG_RUN_DIR/options.json\"
  AWG_OPTIONS=\$AWG_RUN_DIR/options.json
  load_options
"

expect_die junk-order bash -c "
  source '${ROOT}/rootfs/usr/lib/awg/lib.sh'
  AWG_RUN_DIR=\$(mktemp -d)
  jq -n --arg k '$key1' --arg p '$key2' '{
    awg_conf:\"\", private_key:\$k, peer_public_key:\$p, address:\"10.8.0.2/32\",
    endpoint:\"203.0.113.10:51820\", jc:4, jmin:80, jmax:10, s1:0, s2:0,
    h1:\"\",h2:\"\",h3:\"\",h4:\"\", keepalive:25, mtu:1280,
    domains:[], cidrs:[], exclude_cidrs:[], strict:true,
    upstream_dns:[], manage_dns:false, route_timeout:86400, log_level:\"info\"
  }' >\"\$AWG_RUN_DIR/options.json\"
  AWG_OPTIONS=\$AWG_RUN_DIR/options.json
  load_options
"

if [[ $fails -eq 0 ]]; then
  echo "all render tests passed"
else
  echo "${fails} failed" >&2
  exit 1
fi
