#!/usr/bin/env bash
set -Eeuo pipefail

# ==================================================
#  Simple WireGuard Tunnel Manager (v7 - SAFE MULTI + HARD LOCKS)
# ==================================================

APP_NAME="Simple WireGuard Tunnel"
REPO_URL="https://github.com/ach1992/simple-wireguard-tunnel"

WG_DIR="/etc/wireguard"
APP_CONF_DIR="/etc/simple-wireguard"
SYSCTL_FILE="$APP_CONF_DIR/99-simple-wireguard.conf"
IPFWD_PREV_FILE="$APP_CONF_DIR/ip_forward.prev"
IPFWD_MARK_FILE="$APP_CONF_DIR/ip_forward.managed"

RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"
MAG="\033[0;35m"; CYA="\033[0;36m"; WHT="\033[1;37m"; NC="\033[0m"

log( )   { echo -e "${BLU}[INFO]${NC} $*"; }
ok()    { echo -e "${GRN}[OK]${NC} $*"; }
warn()  { echo -e "${YEL}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
pause() { read -r -p "Press Enter to continue..." _; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

fmt_duration() {
  local s="${1:-0}"
  if (( s < 0 )); then s=0; fi
  local d=$((s/86400)); s=$((s%86400))
  local h=$((s/3600));  s=$((s%3600))
  local m=$((s/60));    s=$((s%60))
  if (( d > 0 )); then echo "${d}d ${h}h ${m}m ${s}s"
  elif (( h > 0 )); then echo "${h}h ${m}m ${s}s"
  elif (( m > 0 )); then echo "${m}m ${s}s"
  else echo "${s}s"
  fi
}

wg_handshake_summary() {
  # prints: "never" OR "age=.., at=.."
  local tun="$1"
  local now hs age
  now="$(date +%s)"
  hs="$(wg show "$tun" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
  if [[ -z "${hs:-}" || "$hs" == "0" ]]; then
    echo "Handshake: NEVER"
    return 0
  fi
  age=$(( now - hs ))
  echo "Handshake: OK (age=$(fmt_duration "$age"), at=$(date -d "@$hs" '+%Y-%m-%d %H:%M:%S'))"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
  fi
}

require_cmds() {
  local missing=()
  for c in wg wg-quick ip awk sed grep sysctl systemctl ping; do
    have_cmd "$c" || missing+=("$c")
  done
  if ((${#missing[@]})); then
    err "Missing required commands: ${missing[*]}"
    err "Debian/Ubuntu: apt-get update && apt-get install -y wireguard-tools iproute2 iputils-ping"
    exit 1
  fi
}

ensure_dirs() { mkdir -p "$WG_DIR" "$APP_CONF_DIR"; }

# --- Validation ---
is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.; read -r a b c d <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1
  done
}
is_ifname() { [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; }  # wg0 allowed
is_wg_key() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }
is_port()   { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

default_iface() { ip route 2>/dev/null | awk '/^default/{print $5; exit}'; }
get_iface_ip() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1; }

conf_path_for() { echo "$WG_DIR/${1}.conf"; }
service_for() { echo "wg-quick@${1}.service"; }
tunnel_exists() { [[ -f "$(conf_path_for "$1")" ]]; }

find_first_free_wg_name() {
  local i=0
  while true; do
    local cand="wg${i}"
    tunnel_exists "$cand" || { echo "$cand"; return 0; }
    (( i++ > 4096 )) && return 1
  done
}

suggest_free_tunnel_name() {
  local base="${1:-wg0}"
  if ! tunnel_exists "$base"; then echo "$base"; return 0; fi
  if [[ "$base" =~ ^wg([0-9]+)$ ]]; then
    local n="${BASH_REMATCH[1]}" i=$((n+1))
    while (( i <= 4096 )); do
      local cand="wg${i}"
      tunnel_exists "$cand" || { echo "$cand"; return 0; }
      ((i++))
    done
  fi
  find_first_free_wg_name
}

# --- Multi-tunnel port helpers (LOCAL listen port uniqueness) ---
get_used_listen_ports() {
  ensure_dirs
  shopt -s nullglob
  local files=("$WG_DIR"/*.conf)
  shopt -u nullglob
  ((${#files[@]} == 0)) && return 0

  awk -F'=' '
    /^[[:space:]]*ListenPort[[:space:]]*=/ {
      gsub(/[[:space:]]/, "", $2);
      if ($2 ~ /^[0-9]+$/) print $2
    }' "${files[@]}" 2>/dev/null | sort -n | uniq
}

port_in_use() {
  local p="$1"
  get_used_listen_ports | grep -qx "$p"
}

suggest_free_port() {
  local start="${1:-51820}" p="$start"
  while (( p <= 65535 )); do
    if ! port_in_use "$p"; then echo "$p"; return 0; fi
    ((p++))
  done
  return 1
}

# --- Pair code / tunnel IPs ---
generate_pair_code() { echo "10.$(( (RANDOM % 254) + 1 )).$(( (RANDOM % 254) + 1 ))"; }
parse_pair_code() {
  [[ "$1" =~ ^10\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local x="${BASH_REMATCH[1]}" y="${BASH_REMATCH[2]}"
  (( x >= 0 && x <= 255 && y >= 0 && y <= 255 )) || return 1
  echo "$x $y"
}

recompute_tunnel_ips_from_pair() {
  local parsed; parsed="$(parse_pair_code "${PAIR_CODE}")" || { err "PAIR_CODE invalid."; return 1; }
  local rx="${parsed% *}" ry="${parsed#* }"
  if [[ "${ROLE}" == "source" ]]; then
    TUN_LOCAL_IP="10.${rx}.${ry}.1"; TUN_REMOTE_IP="10.${rx}.${ry}.2"
  else
    TUN_LOCAL_IP="10.${rx}.${ry}.2"; TUN_REMOTE_IP="10.${rx}.${ry}.1"
  fi
}

# --- COPY BLOCK v2 ---
print_copy_block() {
  # in copy block, define ports per side (source listen and dest listen)
  local src_ip dst_ip src_pubkey dst_pubkey src_port dst_port
  if [[ "${ROLE}" == "source" ]]; then
    src_ip="${LOCAL_WAN_IP}"; dst_ip="${REMOTE_WAN_IP}"
    src_pubkey="${LOCAL_PUBKEY}"; dst_pubkey="${REMOTE_PUBKEY}"
    src_port="${LOCAL_LISTEN_PORT}"; dst_port="${REMOTE_LISTEN_PORT}"
  else
    src_ip="${REMOTE_WAN_IP}"; dst_ip="${LOCAL_WAN_IP}"
    src_pubkey="${REMOTE_PUBKEY}"; dst_pubkey="${LOCAL_PUBKEY}"
    src_port="${REMOTE_LISTEN_PORT}"; dst_port="${LOCAL_LISTEN_PORT}"
  fi

  echo "----- SIMPLE_WG_COPY_BLOCK -----"
  echo "PAIR_CODE=${PAIR_CODE}"
  echo "SOURCE_PUBLIC_IP=${src_ip}"
  echo "DEST_PUBLIC_IP=${dst_ip}"
  echo "SOURCE_PUBKEY=${src_pubkey}"
  echo "DEST_PUBKEY=${dst_pubkey}"
  echo "SOURCE_LISTEN_PORT=${src_port}"
  echo "DEST_LISTEN_PORT=${dst_port}"
  echo "TUN_NAME=${TUN_NAME}"
  echo "MTU=${MTU}"
  echo "----- END_COPY_BLOCK -----"
}

prompt_paste_copy_block() {
  COPY_BLOCK_DETECTED=0
  echo
  echo -e "${CYA}Paste COPY BLOCK now${NC} (press Enter to cancel)."
  echo -e "Finish paste by pressing ${WHT}Enter TWICE${NC} on empty lines."
  echo
  local first; read -r -p "Paste the COPY BLOCK (or just Enter to cancel): " first || true
  [[ -z "${first:-}" ]] && return 1

  COPY_BLOCK_DETECTED=1
  local lines=("$first") empty_count=0
  while true; do
    local line; read -r line || true
    if [[ -z "${line:-}" ]]; then
      (( ++empty_count >= 2 )) && break
      echo -e "${YEL}Almost done:${NC} press Enter one more time to finish paste."
      continue
    fi
    empty_count=0; lines+=("$line")
  done

  # reset
  PASTE_PAIR_CODE=""; PASTE_SOURCE_PUBLIC_IP=""; PASTE_DEST_PUBLIC_IP=""
  PASTE_SOURCE_PUBKEY=""; PASTE_DEST_PUBKEY=""
  PASTE_SOURCE_PORT=""; PASTE_DEST_PORT=""
  PASTE_TUN_NAME=""; PASTE_MTU=""

  for kv in "${lines[@]}"; do
    [[ "$kv" =~ ^[A-Z0-9_]+= ]] || continue
    local key="${kv%%=*}" val="${kv#*=}"
    case "$key" in
      PAIR_CODE)          PASTE_PAIR_CODE="$val" ;;
      SOURCE_PUBLIC_IP)   PASTE_SOURCE_PUBLIC_IP="$val" ;;
      DEST_PUBLIC_IP)     PASTE_DEST_PUBLIC_IP="$val" ;;
      SOURCE_PUBKEY)      PASTE_SOURCE_PUBKEY="$val" ;;
      DEST_PUBKEY)        PASTE_DEST_PUBKEY="$val" ;;
      SOURCE_LISTEN_PORT) PASTE_SOURCE_PORT="$val" ;;
      DEST_LISTEN_PORT)   PASTE_DEST_PORT="$val" ;;
      # backward compat:
      LISTEN_PORT)        PASTE_SOURCE_PORT="$val" ;;     # old block (assumes symmetric)
      ENDPOINT_PORT)      PASTE_SOURCE_PORT="$val" ;;
      TUN_NAME)           PASTE_TUN_NAME="$val" ;;
      MTU)                PASTE_MTU="$val" ;;
    esac
  done

  # hard requirements for COPY BLOCK safety
  [[ -n "${PASTE_PAIR_CODE:-}" ]] || { err "COPY BLOCK missing PAIR_CODE."; return 1; }
  [[ -n "${PASTE_SOURCE_PUBLIC_IP:-}" ]] || { err "COPY BLOCK missing SOURCE_PUBLIC_IP."; return 1; }
  [[ -n "${PASTE_DEST_PUBLIC_IP:-}" ]]   || { err "COPY BLOCK missing DEST_PUBLIC_IP."; return 1; }
  [[ -n "${PASTE_SOURCE_PUBKEY:-}" ]]    || { err "COPY BLOCK missing SOURCE_PUBKEY."; return 1; }
  [[ -n "${PASTE_DEST_PUBKEY:-}" ]]      || { err "COPY BLOCK missing DEST_PUBKEY."; return 1; }

  parse_pair_code "$PASTE_PAIR_CODE" >/dev/null || { err "Pasted PAIR_CODE invalid."; return 1; }
  is_ipv4 "$PASTE_SOURCE_PUBLIC_IP" || { err "Pasted SOURCE_PUBLIC_IP invalid."; return 1; }
  is_ipv4 "$PASTE_DEST_PUBLIC_IP"   || { err "Pasted DEST_PUBLIC_IP invalid."; return 1; }
  is_wg_key "$PASTE_SOURCE_PUBKEY"  || { err "Pasted SOURCE_PUBKEY invalid."; return 1; }
  is_wg_key "$PASTE_DEST_PUBKEY"    || { err "Pasted DEST_PUBKEY invalid."; return 1; }

  [[ -n "${PASTE_TUN_NAME:-}" ]] && ! is_ifname "$PASTE_TUN_NAME" && { err "Pasted TUN_NAME invalid."; return 1; }
  [[ -n "${PASTE_SOURCE_PORT:-}" ]] && ! is_port "$PASTE_SOURCE_PORT" && { err "Pasted SOURCE_LISTEN_PORT invalid."; return 1; }
  [[ -n "${PASTE_DEST_PORT:-}" ]] && ! is_port "$PASTE_DEST_PORT" && { err "Pasted DEST_LISTEN_PORT invalid."; return 1; }
  [[ -n "${PASTE_MTU:-}" ]] && ! [[ "$PASTE_MTU" =~ ^[0-9]+$ ]] && { err "Pasted MTU must be numeric."; return 1; }

  ok "COPY BLOCK parsed successfully."
  return 0
}

# --- Sysctl management ---
ipfwd_current() { sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0"; }

ensure_ip_forwarding_managed() {
  ensure_dirs
  if [[ ! -f "$IPFWD_MARK_FILE" ]]; then
    ipfwd_current > "$IPFWD_PREV_FILE" || true
    echo "managed_by_simple_wg" > "$IPFWD_MARK_FILE"
  fi
  {
    echo "# Simple WireGuard sysctl (persist) - generated"
    echo "net.ipv4.ip_forward=1"
  } >"$SYSCTL_FILE"
  chmod 644 "$SYSCTL_FILE"
  sysctl --system >/dev/null 2>&1 || true
}

restore_ip_forwarding_if_last_tunnel() {
  ensure_dirs
  local tunnels; tunnels="$(list_tunnels)"
  [[ -n "${tunnels:-}" ]] && return 0

  if [[ -f "$IPFWD_MARK_FILE" ]]; then
    local prev="0"
    [[ -f "$IPFWD_PREV_FILE" ]] && prev="$(cat "$IPFWD_PREV_FILE" 2>/dev/null || echo 0)"
    rm -f "$SYSCTL_FILE" "$IPFWD_PREV_FILE" "$IPFWD_MARK_FILE" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.ip_forward=${prev}" >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    ok "Restored net.ipv4.ip_forward=${prev} (no tunnels left)."
  fi
}

# --- Config I/O ---
read_meta() {
  local f; f="$(conf_path_for "$1")"; [[ -f "$f" ]] || return 1

  ROLE=$(sed -n 's/^# ROLE=\(.*\)/\1/p' "$f" | head -n1)
  PAIR_CODE=$(sed -n 's/^# PAIR_CODE=\(.*\)/\1/p' "$f" | head -n1)
  LOCAL_WAN_IP=$(sed -n 's/^# LOCAL_WAN_IP=\(.*\)/\1/p' "$f" | head -n1)
  REMOTE_WAN_IP=$(sed -n 's/^# REMOTE_WAN_IP=\(.*\)/\1/p' "$f" | head -n1)
  REMOTE_PUBKEY=$(sed -n 's/^# REMOTE_PUBKEY=\(.*\)/\1/p' "$f" | head -n1)
  REMOTE_LISTEN_PORT=$(sed -n 's/^# REMOTE_LISTEN_PORT=\(.*\)/\1/p' "$f" | head -n1)
  TUN_NAME="$1"

  LOCAL_PRIVKEY=$(awk -F' = ' '/^[[:space:]]*PrivateKey[[:space:]]*=/{print $2; exit}' "$f" || true)
  [[ -n "${LOCAL_PRIVKEY:-}" ]] || { err "Could not read PrivateKey from $f"; return 1; }
  LOCAL_PUBKEY=$(echo "$LOCAL_PRIVKEY" | wg pubkey)

  LOCAL_LISTEN_PORT=$(awk -F' = ' '/^[[:space:]]*ListenPort[[:space:]]*=/{print $2; exit}' "$f" || true)
  MTU=$(awk -F' = ' '/^[[:space:]]*MTU[[:space:]]*=/{print $2; exit}' "$f" || true)

  recompute_tunnel_ips_from_pair
}

write_conf() {
  local f; f="$(conf_path_for "$1")"; ensure_dirs
  cat >"$f" <<EOF
# Simple WireGuard Tunnel Config: ${TUN_NAME}
# ROLE=${ROLE}
# PAIR_CODE=${PAIR_CODE}
# LOCAL_WAN_IP=${LOCAL_WAN_IP}
# REMOTE_WAN_IP=${REMOTE_WAN_IP}
# REMOTE_PUBKEY=${REMOTE_PUBKEY}
# REMOTE_LISTEN_PORT=${REMOTE_LISTEN_PORT}

[Interface]
Address = ${TUN_LOCAL_IP}/30
PrivateKey = ${LOCAL_PRIVKEY}
ListenPort = ${LOCAL_LISTEN_PORT}
MTU = ${MTU}

[Peer]
PublicKey = ${REMOTE_PUBKEY}
AllowedIPs = ${TUN_REMOTE_IP}/32
Endpoint = ${REMOTE_WAN_IP}:${REMOTE_LISTEN_PORT}
PersistentKeepalive = 25
EOF
  chmod 600 "$f"
}

# --- Tunnel listing / selection ---
list_tunnels() {
  ensure_dirs
  shopt -s nullglob
  for f in "$WG_DIR"/*.conf; do
    base="$(basename "$f")"
    echo "${base%.conf}"
  done
  shopt -u nullglob
}

choose_tunnel() {
  local tunnels=()
  while IFS= read -r t; do [[ -n "$t" ]] && tunnels+=("$t"); done < <(list_tunnels)
  ((${#tunnels[@]} == 0)) && { warn "No tunnels found."; return 1; }
  echo -e "${MAG}Available tunnels:${NC}"
  local i
  for i in "${!tunnels[@]}"; do printf "  %s) %s\n" "$((i+1))" "${tunnels[$i]}"; done
  local choice
  while true; do
    read -r -p "Select tunnel [1-${#tunnels[@]}] (Enter=cancel): " choice || true
    [[ -z "${choice:-}" ]] && return 1
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#tunnels[@]} )); then
      SELECTED_TUN="${tunnels[$((choice-1))]}"
      return 0
    fi
    err "Invalid selection."
  done
}

enable_service() { systemctl enable "$(service_for "$1")" >/dev/null 2>&1 || true; }
apply_now() { systemctl restart "$(service_for "$1")" >/dev/null 2>&1 || true; }
stop_disable_service() {
  systemctl stop "$(service_for "$1")" >/dev/null 2>&1 || true
  systemctl disable "$(service_for "$1")" >/dev/null 2>&1 || true
}

# --- Prompts ---
prompt_role() {
  echo "Select server role:"
  echo "  1) Iran (Source)"
  echo "  2) Kharej (Destination)"
  local c
  while true; do
    read -r -p "Enter choice [1-2]: " c || true
    case "${c:-}" in
      1) ROLE="source"; break ;;
      2) ROLE="destination"; break ;;
      *) err "Invalid choice." ;;
    esac
  done
}

prompt_yesno() {
  local prompt="$1" ans
  read -r -p "${prompt} [y/N]: " ans || true
  [[ "${ans:-N}" =~ ^([yY])$ ]]
}

prompt_pair_code_keep() {
  local inp
  read -r -p "PAIR CODE [${PAIR_CODE:-auto}]: " inp || true
  if [[ -z "${inp:-}" ]]; then
    if [[ -n "${PAIR_CODE:-}" ]]; then ok "Keeping existing PAIR CODE: ${PAIR_CODE}"; return 0; fi
    PAIR_CODE="$(generate_pair_code)"; ok "Generated PAIR CODE: ${PAIR_CODE}"; return 0
  fi
  parse_pair_code "$inp" >/dev/null || { err "Invalid PAIR CODE."; return 1; }
  PAIR_CODE="$inp"
}

prompt_mtu() {
  local inp
  read -r -p "MTU [${MTU}]: " inp || true
  inp="${inp:-$MTU}"
  [[ "$inp" =~ ^[0-9]+$ ]] && (( inp >= 1280 && inp <= 1500 )) || { err "Invalid MTU."; return 1; }
  MTU="$inp"
}

prompt_local_listen_port() {
  local inp suggested
  if [[ -z "${LOCAL_LISTEN_PORT:-}" ]]; then
    suggested="$(suggest_free_port 51820 || true)"
    LOCAL_LISTEN_PORT="${suggested:-51820}"
  fi

  while true; do
    if port_in_use "$LOCAL_LISTEN_PORT"; then
      suggested="$(suggest_free_port "$LOCAL_LISTEN_PORT" || true)"
      warn "Local ListenPort ${LOCAL_LISTEN_PORT} is already used by another tunnel."
      [[ -n "$suggested" ]] && warn "Suggested free port: ${suggested}"
    fi

    read -r -p "Local ListenPort [${LOCAL_LISTEN_PORT}]: " inp || true
    inp="${inp:-$LOCAL_LISTEN_PORT}"
    is_port "$inp" || { err "Invalid port."; continue; }
    if port_in_use "$inp"; then
      suggested="$(suggest_free_port "$inp" || true)"
      err "Port $inp is already in use."
      [[ -n "$suggested" ]] && warn "Try: $suggested"
      continue
    fi
    LOCAL_LISTEN_PORT="$inp"
    break
  done
}

prompt_remote_listen_port() {
  local inp
  read -r -p "Remote Endpoint Port [${REMOTE_LISTEN_PORT}]: " inp || true
  inp="${inp:-$REMOTE_LISTEN_PORT}"
  is_port "$inp" || { err "Invalid remote port."; return 1; }
  REMOTE_LISTEN_PORT="$inp"
}

prompt_wan_ips_manual() {
  local inp def_ip; def_ip="$(get_iface_ip "$(default_iface || true)")"
  read -r -p "Local public IPv4 [${LOCAL_WAN_IP:-${def_ip:-}}]: " inp || true
  inp="${inp:-${LOCAL_WAN_IP:-$def_ip}}"
  is_ipv4 "${inp:-}" || { err "Invalid IPv4 address."; return 1; }
  LOCAL_WAN_IP="$inp"

  read -r -p "Remote public IPv4 [${REMOTE_WAN_IP:-}]: " inp || true
  inp="${inp:-${REMOTE_WAN_IP:-}}"
  is_ipv4 "${inp:-}" || { err "Invalid IPv4 address."; return 1; }
  REMOTE_WAN_IP="$inp"
}

prompt_remote_pubkey_manual() {
  local inp
  while true; do
    read -r -p "Remote Peer Public Key [${REMOTE_PUBKEY:-}]: " inp || true
    inp="${inp:-${REMOTE_PUBKEY:-}}"
    is_wg_key "$inp" || { err "Invalid remote public key."; continue; }
    REMOTE_PUBKEY="$inp"
    return 0
  done
}

validate_pre_apply() {
  # hard validation to avoid silent bad tunnels
  is_ifname "$TUN_NAME" || { err "Invalid tunnel name."; return 1; }
  parse_pair_code "$PAIR_CODE" >/dev/null || { err "PAIR_CODE invalid."; return 1; }
  is_ipv4 "$LOCAL_WAN_IP" || { err "Local WAN IP invalid."; return 1; }
  is_ipv4 "$REMOTE_WAN_IP" || { err "Remote WAN IP invalid."; return 1; }
  is_wg_key "$LOCAL_PUBKEY" || { err "Local pubkey invalid."; return 1; }
  is_wg_key "$REMOTE_PUBKEY" || { err "Remote pubkey invalid."; return 1; }
  is_port "$LOCAL_LISTEN_PORT" || { err "Local ListenPort invalid."; return 1; }
  is_port "$REMOTE_LISTEN_PORT" || { err "Remote Endpoint Port invalid."; return 1; }
  [[ "$LOCAL_PUBKEY" != "$REMOTE_PUBKEY" ]] || { err "Local and Remote pubkeys are identical (wrong)."; return 1; }
  [[ "$LOCAL_WAN_IP" != "$REMOTE_WAN_IP" ]] || { err "Local and Remote WAN IPs are identical (wrong)."; return 1; }
  return 0
}

show_summary_and_confirm() {
  echo
  echo -e "${MAG}===== Summary =====${NC}"
  printf "%-24s %s\n" "Role:" "$ROLE"
  printf "%-24s %s\n" "Tunnel name:" "$TUN_NAME"
  printf "%-24s %s\n" "Pair code:" "$PAIR_CODE"
  printf "%-24s %s\n" "Local WAN IP:" "$LOCAL_WAN_IP"
  printf "%-24s %s\n" "Remote WAN IP:" "$REMOTE_WAN_IP"
  printf "%-24s %s\n" "Local tun IP:" "$TUN_LOCAL_IP"
  printf "%-24s %s\n" "Remote tun IP:" "$TUN_REMOTE_IP"
  printf "%-24s %s\n" "Local ListenPort:" "$LOCAL_LISTEN_PORT"
  printf "%-24s %s\n" "Remote Endpoint Port:" "$REMOTE_LISTEN_PORT"
  printf "%-24s %s\n" "MTU:" "$MTU"
  echo
  printf "%-24s %s\n" "Local pubkey:" "$LOCAL_PUBKEY"
  printf "%-24s %s\n" "Remote pubkey:" "$REMOTE_PUBKEY"
  echo
  prompt_yesno "Proceed to create/apply this tunnel?"
}

# --- Actions ---
do_generate_keypair() {
  log "Generating a new WireGuard keypair..."
  local privkey pubkey
  privkey=$(wg genkey)
  pubkey=$(echo "$privkey" | wg pubkey)
  echo
  echo -e "${GRN}Keypair generated successfully:${NC}"
  echo -e "---------------------------------------------------"
  echo -e "${WHT}Private Key:${NC} ${privkey}"
  echo -e "${CYA}Public Key:${NC}  ${pubkey}"
  echo -e "---------------------------------------------------"
  echo -e "${YEL}Copy the Public Key. You will need it on the other server.${NC}"
}

do_create() {
  log "Creating NEW WireGuard tunnel..."
  echo

  prompt_role
  echo

  # defaults
  MTU="1420"
  PAIR_CODE=""
  LOCAL_WAN_IP=""
  REMOTE_WAN_IP=""
  REMOTE_PUBKEY=""
  REMOTE_LISTEN_PORT=""
  LOCAL_LISTEN_PORT=""
  TUN_NAME=""

  PAIR_CODE_LOCKED=0
  WAN_IPS_LOCKED=0
  REMOTE_KEY_LOCKED=0
  REMOTE_PORT_LOCKED=0

  if prompt_yesno "Do you have a COPY BLOCK from the other server?"; then
    if ! prompt_paste_copy_block; then
      err "COPY BLOCK was not parsed. Please try again."
      return 1
    fi

    # hard locks
    PAIR_CODE="$PASTE_PAIR_CODE"; PAIR_CODE_LOCKED=1
    WAN_IPS_LOCKED=1
    REMOTE_KEY_LOCKED=1

    # set MTU (editable)
    [[ -n "${PASTE_MTU:-}" ]] && MTU="$PASTE_MTU"
    [[ -n "${PASTE_TUN_NAME:-}" ]] && TUN_NAME="$PASTE_TUN_NAME"

    # map IPs and keys based on our role
    if [[ "$ROLE" == "source" ]]; then
      LOCAL_WAN_IP="$PASTE_SOURCE_PUBLIC_IP"
      REMOTE_WAN_IP="$PASTE_DEST_PUBLIC_IP"
      REMOTE_PUBKEY="$PASTE_DEST_PUBKEY"
      # remote port = destination listen port if present; else fallback to source port
      if [[ -n "${PASTE_DEST_PORT:-}" ]]; then
        REMOTE_LISTEN_PORT="$PASTE_DEST_PORT"; REMOTE_PORT_LOCKED=1
      elif [[ -n "${PASTE_SOURCE_PORT:-}" ]]; then
        REMOTE_LISTEN_PORT="$PASTE_SOURCE_PORT"
      fi
    else
      LOCAL_WAN_IP="$PASTE_DEST_PUBLIC_IP"
      REMOTE_WAN_IP="$PASTE_SOURCE_PUBLIC_IP"
      REMOTE_PUBKEY="$PASTE_SOURCE_PUBKEY"
      if [[ -n "${PASTE_SOURCE_PORT:-}" ]]; then
        REMOTE_LISTEN_PORT="$PASTE_SOURCE_PORT"; REMOTE_PORT_LOCKED=1
      elif [[ -n "${PASTE_DEST_PORT:-}" ]]; then
        REMOTE_LISTEN_PORT="$PASTE_DEST_PORT"
      fi
    fi

    ok "COPY BLOCK loaded. PAIR_CODE + WAN IPs + Remote PubKey are locked."
    echo
  fi

  # tunnel name smart
  local def_name
  if [[ -n "${TUN_NAME:-}" ]]; then
    def_name="$(suggest_free_tunnel_name "$TUN_NAME")"
  else
    def_name="$(find_first_free_wg_name)"
  fi
  local inp
  read -r -p "Tunnel interface name [${def_name}]: " inp || true
  inp="${inp:-$def_name}"
  is_ifname "$inp" || { err "Invalid interface name."; return 1; }
  tunnel_exists "$inp" && { err "Tunnel name '${inp}' is already taken."; return 1; }
  TUN_NAME="$inp"

  # WAN IPs
  if (( WAN_IPS_LOCKED )); then
    ok "Local WAN IP locked:  ${LOCAL_WAN_IP}"
    ok "Remote WAN IP locked: ${REMOTE_WAN_IP}"
  else
    prompt_wan_ips_manual || return 1
  fi

  # PairCode
  if (( PAIR_CODE_LOCKED )); then
    ok "PAIR CODE locked: ${PAIR_CODE}"
  else
    prompt_pair_code_keep || return 1
  fi
  recompute_tunnel_ips_from_pair || return 1

  # local listen port (unique)
  prompt_local_listen_port || return 1

  # MTU
  prompt_mtu || return 1

  # generate local keys
  log "Generating new keys for this server..."
  LOCAL_PRIVKEY=$(wg genkey)
  LOCAL_PUBKEY=$(echo "$LOCAL_PRIVKEY" | wg pubkey)
  ok "Local keys generated."

  # remote pubkey (locked if copy block)
  if (( REMOTE_KEY_LOCKED )); then
    ok "Remote Public Key locked from COPY BLOCK."
  else
    prompt_remote_pubkey_manual || return 1
  fi

  # remote endpoint port (editable unless explicitly provided)
  if [[ -z "${REMOTE_LISTEN_PORT:-}" ]]; then
    REMOTE_LISTEN_PORT="51820"
  fi
  if (( REMOTE_PORT_LOCKED )); then
    ok "Remote Endpoint Port locked from COPY BLOCK: ${REMOTE_LISTEN_PORT}"
  else
    prompt_remote_listen_port || return 1
  fi

  validate_pre_apply || return 1

  if ! show_summary_and_confirm; then
    warn "Canceled."
    return 0
  fi

  write_conf "$TUN_NAME"
  ensure_ip_forwarding_managed
  enable_service "$TUN_NAME"
  apply_now "$TUN_NAME"

  ok "Tunnel '${TUN_NAME}' created and started."
  echo
  show_info_one "$TUN_NAME"
}

do_edit() {
  if ! choose_tunnel; then warn "No tunnels to edit."; return 0; fi
  local old_tun="$SELECTED_TUN"
  read_meta "$old_tun" || { err "Could not read config for $old_tun"; return 1; }

  log "Editing tunnel: $old_tun"
  warn "Press Enter to keep current values."
  echo

  local r
  echo "Current role: ${ROLE}"
  read -r -p "Change role? (1=Iran/Source, 2=Kharej/Dest, Enter=keep): " r || true
  if [[ -n "${r:-}" ]]; then
    case "$r" in
      1) ROLE="source" ;;
      2) ROLE="destination" ;;
      *) err "Invalid choice."; return 1 ;;
    esac
  fi

  local inp suggested_name
  suggested_name="$(suggest_free_tunnel_name "$TUN_NAME")"
  read -r -p "Tunnel interface name [${TUN_NAME}]: " inp || true
  inp="${inp:-$TUN_NAME}"
  is_ifname "$inp" || { err "Invalid interface name."; return 1; }
  if [[ "$inp" != "$old_tun" ]] && tunnel_exists "$inp"; then
    err "Tunnel name '${inp}' already taken."
    warn "Suggested free name: ${suggested_name}"
    return 1
  fi
  TUN_NAME="$inp"

  prompt_wan_ips_manual || return 1
  prompt_pair_code_keep || return 1
  recompute_tunnel_ips_from_pair || return 1
  prompt_local_listen_port || return 1
  prompt_remote_listen_port || return 1
  prompt_mtu || return 1
  prompt_remote_pubkey_manual || return 1

  if [[ "$TUN_NAME" != "$old_tun" ]]; then
    warn "Tunnel name changed: $old_tun -> $TUN_NAME"
    stop_disable_service "$old_tun"
    rm -f "$(conf_path_for "$old_tun")" || true
  fi

  validate_pre_apply || return 1
  if ! show_summary_and_confirm; then warn "Canceled."; return 0; fi

  write_conf "$TUN_NAME"
  ensure_ip_forwarding_managed
  enable_service "$TUN_NAME"
  apply_now "$TUN_NAME"
  ok "Tunnel '${TUN_NAME}' updated and applied."
  echo
  show_info_one "$TUN_NAME"
}

do_status_one() {
  if ! choose_tunnel; then
    warn "No tunnels found."
    return 0
  fi

  local tun="$SELECTED_TUN"
  read_meta "$tun" || { err "Could not read config for $tun"; return 1; }

  echo -e "${MAG}===== WireGuard Status: ${tun} =====${NC}"
  echo -e "${WHT}Service:${NC}"
  systemctl --no-pager --full status "$(service_for "$tun")" || true
  echo

  echo -e "${WHT}Interface & Peer:${NC}"
  wg show "$tun" || warn "Interface '$tun' is not active."
  echo

  echo -e "${WHT}Handshake:${NC}"
  wg_handshake_summary "$tun"
  # RX/TX
  local peer rx tx
  peer="$(wg show "$tun" peers 2>/dev/null | head -n1)"
  if [[ -n "${peer:-}" ]]; then
    rx="$(wg show "$tun" transfer 2>/dev/null | awk -v p="$peer" '$1==p{print $2" "$3; exit}')"
    tx="$(wg show "$tun" transfer 2>/dev/null | awk -v p="$peer" '$1==p{print $4" "$5; exit}')"
    echo "Transfer: RX=${rx:-0 B} | TX=${tx:-0 B}"
  else
    echo "Transfer: N/A"
  fi
  echo

  echo -e "${WHT}Connectivity:${NC} ping ${TUN_REMOTE_IP}"
  if ping -c 2 -W 2 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    ok "Ping successful."
  else
    warn "Ping FAILED."
  fi
}

do_status_all() {
  echo -e "${MAG}===== WireGuard Status: ALL TUNNELS =====${NC}"
  local tunnels; tunnels="$(list_tunnels)"
  if [[ -z "${tunnels:-}" ]]; then
    warn "No tunnels configured."
    return 0
  fi

  printf "%-10s %-10s %-28s %-22s %-8s\n" "TUN" "SERVICE" "HANDSHAKE" "RX/TX" "PING"
  echo "------------------------------------------------------------------------------------------"

  local tun
  while IFS= read -r tun; do
    [[ -z "${tun:-}" ]] && continue

    # service state
    local svc state
    svc="$(service_for "$tun")"
    state="$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")"

    # handshake age
    local hs now age hs_epoch hs_txt
    now="$(date +%s)"
    hs_epoch="$(wg show "$tun" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
    if [[ -z "${hs_epoch:-}" || "$hs_epoch" == "0" ]]; then
      hs_txt="NEVER"
    else
      age=$(( now - hs_epoch ))
      hs_txt="OK age=$(fmt_duration "$age")"
    fi

    # rx/tx
    local peer rx tx rxtx
    peer="$(wg show "$tun" peers 2>/dev/null | head -n1)"
    if [[ -n "${peer:-}" ]]; then
      rx="$(wg show "$tun" transfer 2>/dev/null | awk -v p="$peer" '$1==p{print $2$3; exit}')"
      tx="$(wg show "$tun" transfer 2>/dev/null | awk -v p="$peer" '$1==p{print $4$5; exit}')"
      rxtx="${rx:-0B}/${tx:-0B}"
    else
      rxtx="N/A"
    fi

    # ping (needs TUN_REMOTE_IP -> from metadata)
    local ping_txt="N/A"
    if read_meta "$tun" >/dev/null 2>&1; then
      if ping -c 1 -W 1 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
        ping_txt="OK"
      else
        ping_txt="FAIL"
      fi
    fi

    printf "%-10s %-10s %-28s %-22s %-8s\n" "$tun" "$state" "$hs_txt" "$rxtx" "$ping_txt"
  done <<< "$tunnels"

  echo
  echo -e "${WHT}Tip:${NC} If HANDSHAKE is NEVER/old, check keys/endpoint/UDP. If HANDSHAKE OK but PING FAIL, check AllowedIPs/routes."
}

show_info_one() {
  local tun_to_show="${1:-}"
  if [[ -z "$tun_to_show" ]]; then
    if ! choose_tunnel; then warn "No tunnels found."; return 0; fi
    tun_to_show="$SELECTED_TUN"
  fi
  read_meta "$tun_to_show" || { err "Could not read config for $tun_to_show"; return 1; }

  echo -e "${MAG}===== WireGuard Info: ${tun_to_show} =====${NC}"
  printf "%-24s %s\n" "Role:" "${ROLE}"
  printf "%-24s %s\n" "Pair Code:" "${PAIR_CODE}"
  printf "%-24s %s\n" "Tunnel Name:" "${TUN_NAME}"
  printf "%-24s %s\n" "Local ListenPort:" "${LOCAL_LISTEN_PORT}"
  printf "%-24s %s\n" "Remote Endpoint Port:" "${REMOTE_LISTEN_PORT}"
  printf "%-24s %s\n" "MTU:" "${MTU}"
  echo
  printf "%-24s %s\n" "Local Public IP:" "${LOCAL_WAN_IP}"
  printf "%-24s %s\n" "Local Tunnel IP:" "${TUN_LOCAL_IP}"
  printf "%-24s %s\n" "Local Public Key:" "${LOCAL_PUBKEY}"
  echo
  printf "%-24s %s\n" "Remote Public IP:" "${REMOTE_WAN_IP}"
  printf "%-24s %s\n" "Remote Tunnel IP:" "${TUN_REMOTE_IP}"
  printf "%-24s %s\n" "Remote Public Key:" "${REMOTE_PUBKEY}"
  echo
  echo -e "${CYA}COPY BLOCK (for other server):${NC}"
  print_copy_block
}

do_delete() {
  if ! choose_tunnel; then warn "No tunnels to delete."; return 0; fi
  local tun="$SELECTED_TUN"
  warn "This will permanently delete tunnel '$tun' and its config file."
  local yn; read -r -p "Are you sure? [y/N]: " yn || true
  [[ ! "$yn" =~ ^([yY])$ ]] && { log "Canceled."; return 0; }

  stop_disable_service "$tun"
  rm -f "$(conf_path_for "$tun")" || true
  ok "Deleted tunnel '$tun'."
  restore_ip_forwarding_if_last_tunnel
}

banner() {
  echo -e "${MAG}========================================${NC}"
  echo -e "${WHT}  ${APP_NAME}${NC}"
  echo -e "${YEL}  Repo:${NC} ${BLU}${REPO_URL}${NC}"
  echo -e "${MAG}========================================${NC}"
}

menu() {
  while true; do
    set +e
    clear || true
    banner
    echo -e "${CYA}1)${NC} Create tunnel"
    echo -e "${CYA}2)${NC} Edit tunnel"
    echo -e "${CYA}3)${NC} Status (one tunnel)"
    echo -e "${CYA}4)${NC} Status (all tunnels)"
    echo -e "${CYA}5)${NC} Info / COPY BLOCK"
    echo -e "${CYA}6)${NC} Delete tunnel"
    echo -e "${YEL}7)${NC} Generate Keypair"
    echo -e "${CYA}0)${NC} Exit"
    echo -e "${MAG}----------------------------------------${NC}"

    local c; read -r -p "Select an option [0-7]: " c || true
    case "${c:-}" in
      1) do_create || true; pause ;;
      2) do_edit || true; pause ;;
      3) do_status_one || true; pause ;;
      4) do_status_all || true; pause ;;
      5) show_info_one || true; pause ;;
      6) do_delete || true; pause ;;
      7) do_generate_keypair || true; pause ;;
      0) exit 0 ;;
      *) err "Invalid selection."; pause ;;
    esac
    set -e
  done
}

main() {
  require_root
  require_cmds
  ensure_dirs
  menu
}

main "$@"
