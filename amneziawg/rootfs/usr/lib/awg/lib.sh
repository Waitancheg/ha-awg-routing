# shellcheck shell=bash
# Shared helpers for the AmneziaWG selective-routing add-on.
# The tunnel never owns the main default route: only fwmark 0x77 is looked up
# in table 51820, whose default is awg0 (or a blackhole while strict mode is down).

AWG_IF=awg0
AWG_TABLE=51820
AWG_MARK=0x77
# Just before Tailscale's usual 5210 rule, and only for our mark, so tailscale0
# and 100.64.0.0/10 are left on Tailscale's own rules.
AWG_RULE_PRIO=5100
AWG_ENDPOINT_RULE_PRIO=5050
AWG_NFT=awg_pbr
# Used by awg-monitor after this file is sourced.
# shellcheck disable=SC2034
AWG_HANDSHAKE_MAX_AGE=180
HEALTH_PORT=10799
AWG_RUN_DIR=${AWG_RUN_DIR:-/run/awg}
AWG_OPTIONS=${AWG_OPTIONS:-/data/options.json}

log() { printf '[awg] %s\n' "$*"; }
die() { printf '[awg] %s\n' "$*" >&2; exit 1; }

trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

valid_ipv4() {
  local ip=$1 o1 o2 o3 o4
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]}
  [[ $o1 -le 255 && $o2 -le 255 && $o3 -le 255 && $o4 -le 255 ]]
}

valid_cidr() {
  local cidr=$1 prefix
  [[ $cidr == */* ]] || return 1
  prefix=${cidr#*/}
  valid_ipv4 "${cidr%/*}" || return 1
  [[ $prefix =~ ^[0-9]+$ && $prefix -le 32 ]] || return 1
  [[ $cidr != 0.0.0.0/0 ]]
}

valid_addr() {
  local addr=$1
  [[ $addr == */* ]] && valid_cidr "$addr"
}

valid_domain() {
  local d=$1
  [[ ${#d} -le 253 && $d =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || return 1
  [[ $d == *.* && $d != *..* && $d != *.-* && $d != *-.* ]]
}

normalize_domain() {
  local d=$1
  d=${d%.}
  d=${d,,}
  d=${d#\*.}
  printf '%s' "$d"
}

valid_key() {
  [[ $1 =~ ^[A-Za-z0-9+/]{42,44}={0,2}$ ]]
}

valid_uint() {
  [[ $1 =~ ^[0-9]+$ && $1 -le 65535 ]]
}

valid_hrange() {
  local v=$1 left right
  if [[ $v =~ ^[0-9]+$ ]]; then
    [[ $v -le 4294967295 ]]
    return
  fi
  [[ $v =~ ^([0-9]+)-([0-9]+)$ ]] || return 1
  left=${BASH_REMATCH[1]} right=${BASH_REMATCH[2]}
  [[ $left -le 4294967295 && $right -le 4294967295 && $left -le $right ]]
}

load_options() {
  [[ -f $AWG_OPTIONS ]] || die "config file not found: ${AWG_OPTIONS}"
  OPT_JSON=$(<"$AWG_OPTIONS")
  jq -e 'type == "object"' <<<"$OPT_JSON" >/dev/null || die "options.json must be a JSON object"

  opt_awg_conf=$(jq -r '.awg_conf // ""' <<<"$OPT_JSON")
  opt_private_key=$(jq -r '.private_key // ""' <<<"$OPT_JSON")
  opt_address=$(jq -r '.address // ""' <<<"$OPT_JSON")
  opt_jc=$(jq -r '.jc // 0' <<<"$OPT_JSON")
  opt_jmin=$(jq -r '.jmin // 0' <<<"$OPT_JSON")
  opt_jmax=$(jq -r '.jmax // 0' <<<"$OPT_JSON")
  opt_s1=$(jq -r '.s1 // 0' <<<"$OPT_JSON")
  opt_s2=$(jq -r '.s2 // 0' <<<"$OPT_JSON")
  opt_h1=$(jq -r '.h1 // ""' <<<"$OPT_JSON")
  opt_h2=$(jq -r '.h2 // ""' <<<"$OPT_JSON")
  opt_h3=$(jq -r '.h3 // ""' <<<"$OPT_JSON")
  opt_h4=$(jq -r '.h4 // ""' <<<"$OPT_JSON")
  opt_peer_public_key=$(jq -r '.peer_public_key // ""' <<<"$OPT_JSON")
  opt_preshared_key=$(jq -r '.preshared_key // ""' <<<"$OPT_JSON")
  opt_endpoint=$(jq -r '.endpoint // ""' <<<"$OPT_JSON")
  opt_keepalive=$(jq -r '.keepalive // 25' <<<"$OPT_JSON")
  opt_mtu=$(jq -r '.mtu // 1280' <<<"$OPT_JSON")
  opt_strict=$(jq -r 'if has("strict") then .strict else true end' <<<"$OPT_JSON")
  opt_warmup=$(jq -r 'if has("warmup") then .warmup else true end' <<<"$OPT_JSON")
  opt_route_timeout=$(jq -r '.route_timeout // 86400' <<<"$OPT_JSON")
  opt_log_level=$(jq -r '.log_level // "info"' <<<"$OPT_JSON")

  mapfile -t opt_domains < <(jq -r '.domains // [] | .[]' <<<"$OPT_JSON")
  mapfile -t opt_cidrs < <(jq -r '.cidrs // [] | .[]' <<<"$OPT_JSON")
  mapfile -t opt_exclude < <(jq -r '.exclude_cidrs // [] | .[]' <<<"$OPT_JSON")

  [[ $opt_strict == true || $opt_strict == false ]] || die "strict must be true or false"
  [[ $opt_warmup == true || $opt_warmup == false ]] || die "warmup must be true or false"
  if ! valid_uint "$opt_jc" || ! valid_uint "$opt_jmin" || ! valid_uint "$opt_jmax"; then
    die "Jc/Jmin/Jmax must be integers"
  fi
  if ! valid_uint "$opt_s1" || ! valid_uint "$opt_s2"; then
    die "S1/S2 must be integers"
  fi
  valid_uint "$opt_keepalive" || die "keepalive must be an integer"
  if ! valid_uint "$opt_mtu" || [[ $opt_mtu -lt 1280 || $opt_mtu -gt 1500 ]]; then
    die "mtu must be 1280-1500"
  fi
  [[ $opt_route_timeout =~ ^[0-9]+$ && $opt_route_timeout -ge 60 && $opt_route_timeout -le 604800 ]] || die "route_timeout must be 60-604800 seconds"
  case $opt_log_level in
    trace | debug | info | notice | warning | error | fatal) ;;
    *) die "unknown log_level" ;;
  esac
  [[ -z $opt_h1 ]] || valid_hrange "$opt_h1" || die "bad H1"
  [[ -z $opt_h2 ]] || valid_hrange "$opt_h2" || die "bad H2"
  [[ -z $opt_h3 ]] || valid_hrange "$opt_h3" || die "bad H3"
  [[ -z $opt_h4 ]] || valid_hrange "$opt_h4" || die "bad H4"

  local d c
  DOMAINS=()
  for d in "${opt_domains[@]}"; do
    [[ -n $d ]] || continue
    d=$(normalize_domain "$d")
    valid_domain "$d" || die "invalid domain: ${d}"
    DOMAINS+=("$d")
  done
  CIDRS=()
  for c in "${opt_cidrs[@]}"; do
    [[ -n $c ]] || continue
    if [[ $c == 0.0.0.0/0 ]]; then
      die "0.0.0.0/0 is not allowed: this add-on must not take the default route"
    fi
    valid_cidr "$c" || die "invalid CIDR: ${c}"
    CIDRS+=("$c")
  done
  EXCLUDES=()
  for c in "${opt_exclude[@]}"; do
    [[ -n $c ]] || continue
    valid_cidr "$c" || die "invalid exclude CIDR: ${c}"
    EXCLUDES+=("$c")
  done
  if [[ $opt_jc -gt 0 || $opt_jmin -gt 0 || $opt_jmax -gt 0 ]]; then
    [[ $opt_jc -gt 0 && $opt_jmax -gt 0 && $opt_jmin -le $opt_jmax ]] || die "when junk packets are used, Jc > 0 and Jmin <= Jmax"
  fi
  if [[ ${#DOMAINS[@]} -eq 0 && ${#CIDRS[@]} -eq 0 ]]; then
    log "warning: domains and cidrs are both empty; the tunnel will come up but carry no routed traffic"
  fi
}

resolve_name() {
  local name=$1 ip
  # System resolver only. Do not pin a server: that would bypass MagicDNS and DHCP DNS.
  ip=$(dig +short +time=2 +tries=1 A "$name" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)
  if valid_ipv4 "${ip:-}"; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
}

canonical_iface_key() {
  case ${1,,} in
    privatekey) printf PrivateKey ;;
    listenport) printf ListenPort ;;
    jc) printf Jc ;;
    jmin) printf Jmin ;;
    jmax) printf Jmax ;;
    s1) printf S1 ;;
    s2) printf S2 ;;
    s3) printf S3 ;;
    s4) printf S4 ;;
    h1) printf H1 ;;
    h2) printf H2 ;;
    h3) printf H3 ;;
    h4) printf H4 ;;
    i1) printf I1 ;;
    i2) printf I2 ;;
    i3) printf I3 ;;
    i4) printf I4 ;;
    i5) printf I5 ;;
    headerprotectionkey) printf HeaderProtectionKey ;;
    contentpaddingaddition) printf ContentPaddingAddition ;;
    rekeyaftertime) printf RekeyAfterTime ;;
    rekeytimeout) printf RekeyTimeout ;;
    rejectaftertime) printf RejectAfterTime ;;
    keepalivetimeout) printf KeepaliveTimeout ;;
    maxhandshakeattempts) printf MaxHandshakeAttempts ;;
    randomtrailers) printf RandomTrailers ;;
    disablecookies) printf DisableCookies ;;
    *) return 1 ;;
  esac
}

canonical_peer_key() {
  case ${1,,} in
    publickey) printf PublicKey ;;
    presharedkey) printf PresharedKey ;;
    endpoint) printf Endpoint ;;
    persistentkeepalive) printf PersistentKeepalive ;;
    advancedsecurity) printf AdvancedSecurity ;;
    *) return 1 ;;
  esac
}

reset_conf_state() {
  unset IFACE PEER
  declare -gA IFACE=()
  declare -gA PEER=()
  AWG_ADDRESS=""
  AWG_MTU=""
  ENDPOINT_HOST=""
  ENDPOINT_PORT=""
  ALLOWEDIPS_LOGGED=0
}

take_value() {
  local key=$1 val=$2 canon section=$3
  case ${key,,} in
    address)
      AWG_ADDRESS=$val
      return
      ;;
    mtu)
      AWG_MTU=$val
      return
      ;;
    dns)
      log "ignoring DNS=: host resolver settings are not changed"
      return
      ;;
    table)
      log "ignoring Table=: no routes are installed from the AmneziaWG config"
      return
      ;;
    fwmark)
      log "ignoring FwMark=: tunnel packets must not receive the policy-routing mark"
      return
      ;;
    preup | postup | predown | postdown | saveconfig)
      log "ignoring ${key}: hooks are not run"
      return
      ;;
    allowedips)
      if [[ $ALLOWEDIPS_LOGGED -eq 0 ]]; then
        log "AllowedIPs is forced to 0.0.0.0/0 inside the tunnel so selected destinations can be encrypted; the system default route stays unchanged"
        ALLOWEDIPS_LOGGED=1
      fi
      return
      ;;
  esac
  if [[ $section == iface ]]; then
    canon=$(canonical_iface_key "$key") || die "unrecognized Interface key '${key}' (AWG 3.1 allowlist)"
    IFACE[$canon]=$val
  else
    canon=$(canonical_peer_key "$key") || die "unrecognized Peer key '${key}'"
    if [[ $canon == Endpoint ]]; then
      parse_endpoint "$val"
      return
    fi
    PEER[$canon]=$val
  fi
}

parse_endpoint() {
  local ep=$1
  [[ $ep == *'['* || $ep == *']]'* ]] && die "IPv6 endpoints are not supported"
  [[ $ep == *:* ]] || die "endpoint must be host:port"
  ENDPOINT_PORT=${ep##*:}
  ENDPOINT_HOST=${ep%:*}
  [[ -n $ENDPOINT_HOST && $ENDPOINT_HOST != *:* ]] || die "endpoint host must be an IPv4 address or a DNS name"
  [[ $ENDPOINT_PORT =~ ^[0-9]+$ && $ENDPOINT_PORT -ge 1 && $ENDPOINT_PORT -le 65535 ]] || die "endpoint port is invalid"
}

parse_pasted() {
  local line section="" seen_peer=0 key val
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line//$'\r'/}
    [[ $line =~ ^[[:space:]]*# ]] && continue
    line=$(trim "$line")
    [[ -n $line ]] || continue
    local lower=${line,,}
    if [[ $lower == "[interface]" ]]; then
      section=iface
      continue
    fi
    if [[ $lower == "[peer]" ]]; then
      [[ $seen_peer -eq 0 ]] || die "only one [Peer] is supported"
      seen_peer=1
      section=peer
      continue
    fi
    [[ -n $section ]] || die "line is outside [Interface]/[Peer]"
    [[ $line == *"="* ]] || die "expected Key = value"
    key=$(trim "${line%%=*}")
    val=$(trim "${line#*=}")
    [[ $val != *$'\n'* && $val != *'#'* ]] || die "values must be a single line without '#'"
    [[ -n $key && -n $val ]] || continue
    take_value "$key" "$val" "$section"
  done <<<"$1"
}

build_structured() {
  [[ -n $opt_private_key && -n $opt_peer_public_key && -n $opt_endpoint && -n $opt_address ]] ||
    die "paste awg_conf or set private_key, address, peer_public_key and endpoint"
  valid_key "$opt_private_key" || die "private_key is not a WireGuard key"
  valid_key "$opt_peer_public_key" || die "peer_public_key is not a WireGuard key"
  if [[ -n $opt_preshared_key ]]; then
    valid_key "$opt_preshared_key" || die "preshared_key is not a WireGuard key"
  fi
  valid_addr "$opt_address" || die "address must be an IPv4 CIDR, for example 10.8.0.2/32"
  AWG_ADDRESS=$opt_address
  parse_endpoint "$opt_endpoint"
  IFACE[PrivateKey]=$opt_private_key
  if [[ $opt_jc -gt 0 ]]; then
    IFACE[Jc]=$opt_jc
    IFACE[Jmin]=$opt_jmin
    IFACE[Jmax]=$opt_jmax
  fi
  [[ $opt_s1 -gt 0 ]] && IFACE[S1]=$opt_s1
  [[ $opt_s2 -gt 0 ]] && IFACE[S2]=$opt_s2
  [[ -n $opt_h1 ]] && IFACE[H1]=$opt_h1
  [[ -n $opt_h2 ]] && IFACE[H2]=$opt_h2
  [[ -n $opt_h3 ]] && IFACE[H3]=$opt_h3
  [[ -n $opt_h4 ]] && IFACE[H4]=$opt_h4
  PEER[PublicKey]=$opt_peer_public_key
  [[ -n $opt_preshared_key ]] && PEER[PresharedKey]=$opt_preshared_key
  [[ $opt_keepalive -gt 0 ]] && PEER[PersistentKeepalive]=$opt_keepalive
}

check_junk_pair() {
  if [[ -n ${IFACE[Jc]:-} || -n ${IFACE[Jmin]:-} || -n ${IFACE[Jmax]:-} ]]; then
    local jc=${IFACE[Jc]:-0} jmin=${IFACE[Jmin]:-0} jmax=${IFACE[Jmax]:-0}
    if ! valid_uint "$jc" || ! valid_uint "$jmin" || ! valid_uint "$jmax"; then
      die "Jc/Jmin/Jmax must be integers"
    fi
    [[ $jmin -le $jmax ]] || die "Jmin must be <= Jmax"
  fi
}

write_awg_conf() {
  local k
  if valid_ipv4 "$ENDPOINT_HOST"; then
    ENDPOINT_IP=$ENDPOINT_HOST
  else
    ENDPOINT_IP=$(resolve_name "$ENDPOINT_HOST") || die "cannot resolve endpoint ${ENDPOINT_HOST}"
  fi
  PEER[Endpoint]="${ENDPOINT_IP}:${ENDPOINT_PORT}"
  PEER[AllowedIPs]=0.0.0.0/0
  if [[ -z ${PEER[PersistentKeepalive]+x} && $opt_keepalive -gt 0 ]]; then
    PEER[PersistentKeepalive]=$opt_keepalive
  fi
  [[ -n $AWG_ADDRESS ]] || die "Interface Address is required (for example 10.8.0.2/32)"
  valid_addr "$AWG_ADDRESS" || die "Address must be an IPv4 CIDR"
  AWG_ADDR_HOST=${AWG_ADDRESS%%/*}
  if [[ -z $AWG_MTU ]]; then
    AWG_MTU=$opt_mtu
  fi
  [[ $AWG_MTU =~ ^[0-9]+$ && $AWG_MTU -ge 1280 && $AWG_MTU -le 1500 ]] || die "MTU must be 1280-1500"
  AWG_MSS=$((AWG_MTU - 40))
  valid_key "${IFACE[PrivateKey]:-}" || die "PrivateKey is missing or invalid"
  valid_key "${PEER[PublicKey]:-}" || die "PublicKey is missing or invalid"
  if [[ -n ${PEER[PresharedKey]:-} ]]; then
    valid_key "${PEER[PresharedKey]}" || die "PresharedKey is invalid"
  fi
  check_junk_pair

  PEER_PUB=${PEER[PublicKey]}
  umask 077
  {
    printf '[Interface]\n'
    for k in PrivateKey ListenPort Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 \
      HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime \
      KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies; do
      [[ -n ${IFACE[$k]+x} ]] && printf '%s = %s\n' "$k" "${IFACE[$k]}"
    done
    printf '\n[Peer]\n'
    for k in PublicKey PresharedKey Endpoint AllowedIPs PersistentKeepalive AdvancedSecurity; do
      [[ -n ${PEER[$k]+x} ]] && printf '%s = %s\n' "$k" "${PEER[$k]}"
    done
  } >"${AWG_RUN_DIR}/awg0.conf"
  chmod 600 "${AWG_RUN_DIR}/awg0.conf"
}

prepare_config() {
  mkdir -p "$AWG_RUN_DIR"
  chmod 700 "$AWG_RUN_DIR"
  reset_conf_state
  local pasted
  pasted=$(trim "$opt_awg_conf")
  if [[ -n ${pasted//[[:space:]]/} ]]; then
    log "using awg_conf; structured key fields are ignored"
    parse_pasted "$pasted"
  else
    build_structured
  fi
  write_awg_conf
  write_domains
  write_runtime_env
}

write_domains() {
  local d
  : >"${AWG_RUN_DIR}/domains"
  for d in "${DOMAINS[@]}"; do
    printf '%s\n' "$d" >>"${AWG_RUN_DIR}/domains"
  done
}

write_runtime_env() {
  {
    printf 'AWG_ADDRESS=%q\n' "$AWG_ADDRESS"
    printf 'AWG_ADDR_HOST=%q\n' "$AWG_ADDR_HOST"
    printf 'AWG_MTU=%q\n' "$AWG_MTU"
    printf 'AWG_MSS=%q\n' "$AWG_MSS"
    printf 'ENDPOINT_HOST=%q\n' "$ENDPOINT_HOST"
    printf 'ENDPOINT_PORT=%q\n' "$ENDPOINT_PORT"
    printf 'ENDPOINT_IP=%q\n' "$ENDPOINT_IP"
    printf 'PEER_PUB=%q\n' "$PEER_PUB"
    printf 'opt_strict=%q\n' "$opt_strict"
    printf 'opt_warmup=%q\n' "$opt_warmup"
    printf 'opt_log_level=%q\n' "$opt_log_level"
    printf 'opt_route_timeout=%q\n' "$opt_route_timeout"
    printf 'opt_keepalive=%q\n' "$opt_keepalive"
    case $opt_log_level in
      trace | debug) printf 'LOG_LEVEL=%q\n' verbose ;;
      *) printf 'LOG_LEVEL=%q\n' error ;;
    esac
  } >"${AWG_RUN_DIR}/runtime.env"
  chmod 600 "${AWG_RUN_DIR}/runtime.env"
}

linked_subnet() {
  local iface=$1
  ip -4 route show dev "$iface" scope link 2>/dev/null | awk 'NR == 1 { print $1 }'
}

nft_up() {
  local -a excl=()
  local subnet="" conf="${AWG_RUN_DIR}/nft.conf"
  excl=(
    0.0.0.0/8
    127.0.0.0/8
    169.254.0.0/16
    100.64.0.0/10
    172.30.32.0/23
    224.0.0.0/4
  )
  if ip link show hassio >/dev/null 2>&1; then
    subnet=$(linked_subnet hassio || true)
    [[ -n $subnet ]] && excl+=("$subnet")
  fi
  excl+=("${EXCLUDES[@]}")
  excl+=("${ENDPOINT_IP}/32")

  {
    printf 'table inet %s {\n' "$AWG_NFT"
    printf '  set routed_v4 { type ipv4_addr; flags timeout; timeout %ss; }\n' "$opt_route_timeout"
    printf '  set routed_v6 { type ipv6_addr; flags timeout; timeout %ss; }\n' "$opt_route_timeout"
    printf '  set cidrs_v4 { type ipv4_addr; flags interval; }\n'
    printf '  set exclude_v4 { type ipv4_addr; flags interval; auto-merge; }\n'
    printf '  chain tag {\n'
    printf '    iifname "%s" return\n' "$AWG_IF"
    printf '    ip daddr @exclude_v4 return\n'
    printf '    ip daddr @cidrs_v4 meta mark set %s counter comment "awg cidr"\n' "$AWG_MARK"
    printf '    ip daddr @routed_v4 meta mark set %s counter comment "awg domain"\n' "$AWG_MARK"
    printf '  }\n'
    printf '  chain output { type route hook output priority mangle; policy accept; jump tag; }\n'
    printf '  chain prerouting { type filter hook prerouting priority mangle; policy accept; jump tag; }\n'
    printf '  chain postrouting { type filter hook postrouting priority mangle; policy accept; oifname "%s" tcp flags syn tcp option maxseg size set %s; }\n' "$AWG_IF" "$AWG_MSS"
    if [[ $opt_strict == true ]]; then
      printf '  chain v6out { type filter hook output priority filter; policy accept; ip6 daddr @routed_v6 reject with icmpv6 admin-prohibited; }\n'
      printf '  chain v6fwd { type filter hook forward priority filter; policy accept; ip6 daddr @routed_v6 reject with icmpv6 admin-prohibited; }\n'
    fi
    printf '  chain health { type filter hook input priority filter; policy accept; tcp dport %s ip saddr != { 127.0.0.0/8, 172.30.32.0/23 } drop; }\n' "$HEALTH_PORT"
    printf '}\n'
  } >"$conf"
  nft delete table inet "$AWG_NFT" 2>/dev/null || true
  nft -f "$conf"
  nft_add_elements exclude_v4 "${excl[@]}"
  if [[ ${#CIDRS[@]} -gt 0 ]]; then
    nft_add_elements cidrs_v4 "${CIDRS[@]}"
  fi
}

nft_add_elements() {
  local set=$1
  shift
  local -a items=()
  local item seen=" "
  for item in "$@"; do
    [[ -n $item ]] || continue
    [[ $seen == *" ${item} "* ]] && continue
    seen+=" ${item} "
    items+=("$item")
  done
  [[ ${#items[@]} -gt 0 ]] || return 0
  local joined
  joined=$(printf '%s, ' "${items[@]}")
  joined=${joined%, }
  nft add element inet "$AWG_NFT" "$set" "{ ${joined} }"
}

cleanup_dataplane() {
  nft delete table inet "$AWG_NFT" 2>/dev/null || true
  ip rule del priority "$AWG_RULE_PRIO" 2>/dev/null || true
  ip rule del priority "$AWG_ENDPOINT_RULE_PRIO" 2>/dev/null || true
  ip route flush table "$AWG_TABLE" 2>/dev/null || true
  if ip link show "$AWG_IF" >/dev/null 2>&1; then
    ip link del "$AWG_IF" 2>/dev/null || true
  fi
  rm -f "/var/run/amneziawg/${AWG_IF}.sock"
}

ensure_fwmark_rule() {
  local cur
  cur=$(ip rule show priority "$AWG_RULE_PRIO" || true)
  if [[ -n $cur ]]; then
    if [[ $cur == *"fwmark ${AWG_MARK}"* && $cur == *"lookup ${AWG_TABLE}"* ]]; then
      return 0
    fi
    die "ip rule priority ${AWG_RULE_PRIO} is already used: ${cur}"
  fi
  ip rule add fwmark "$AWG_MARK" lookup "$AWG_TABLE" priority "$AWG_RULE_PRIO"
}

ensure_endpoint_rule() {
  local cur
  cur=$(ip rule show priority "$AWG_ENDPOINT_RULE_PRIO" || true)
  if [[ -n $cur && $cur != *"to ${ENDPOINT_IP}"* ]]; then
    log "replacing ip rule priority ${AWG_ENDPOINT_RULE_PRIO}: ${cur}"
    ip rule del priority "$AWG_ENDPOINT_RULE_PRIO"
  fi
  if [[ -z $(ip rule show priority "$AWG_ENDPOINT_RULE_PRIO") ]]; then
    # Outer UDP to the server must use the main table (LTE), even if it is marked.
    ip rule add to "$ENDPOINT_IP" lookup main priority "$AWG_ENDPOINT_RULE_PRIO"
  fi
}

set_route() {
  local mode=$1
  if [[ $mode == up ]]; then
    ip route del blackhole default table "$AWG_TABLE" 2>/dev/null || true
    ip route replace default dev "$AWG_IF" src "$AWG_ADDR_HOST" table "$AWG_TABLE"
    return
  fi
  if [[ ${opt_strict:-true} == true ]]; then
    ip route del default table "$AWG_TABLE" 2>/dev/null || true
    ip route replace blackhole default table "$AWG_TABLE"
  else
    ip route del default table "$AWG_TABLE" 2>/dev/null || true
    ip route del blackhole default table "$AWG_TABLE" 2>/dev/null || true
  fi
}

rules_up() {
  ensure_fwmark_rule
  ensure_endpoint_rule
  set_route down
}

ha_state() {
  local entity=$1 body=$2 http
  [[ -n ${SUPERVISOR_TOKEN:-} ]] || return 0
  http=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${SUPERVISOR_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "http://supervisor/core/api/states/${entity}" || true)
  [[ $http == 200 || $http == 201 ]]
}

count_routed() {
  local ips
  ips=$(nft list set inet "$AWG_NFT" routed_v4 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' || true)
  if [[ -z $ips ]]; then
    printf '0'
  else
    printf '%s\n' "$ips" | sort -u | wc -l | tr -d '[:space:]'
  fi
}
