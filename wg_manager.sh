#!/usr/bin/env bash
set -Eeuo pipefail

# ==================================================
#  Simple WireGuard Tunnel Manager (v4 - FIXED)
# ==================================================

APP_NAME="Simple WireGuard Tunnel"
REPO_URL="https://github.com/ach1992/simple-wireguard-tunnel"

WG_DIR="/etc/wireguard"
APP_CONF_DIR="/etc/simple-wireguard"
SYSCTL_FILE="$APP_CONF_DIR/99-simple-wireguard.conf"

RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"
MAG="\033[0;35m"; CYA="\033[0;36m"; WHT="\033[1;37m"; NC="\033[0m"

log( )   { echo -e "${BLU}[INFO]${NC} $*"; }
ok()    { echo -e "${GRN}[OK]${NC} $*"; }
warn()  { echo -e "${YEL}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
pause() { read -r -p "Press Enter to continue..." _; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

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

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.; read -r a b c d <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1
  done
}
is_ifname() { [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; }   # wg0 هم مجاز شد
is_wg_key() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }
is_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

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

generate_pair_code() { echo "10.$(( (RANDOM % 254) + 1 )).$(( (RANDOM % 254) + 1 ))"; }
parse_pair_code() {
  [[ "$1" =~ ^10\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local x="${BASH_REMATCH[1]}" y="${BASH_REMATCH[2]}"
  (( x >= 0 && x <= 255 && y >= 0 && y <= 255 )) || return 1
  echo "$x $y"
}

recompute_tunnel_ips_from_pair() {
  local parsed; parsed="$(parse_pair_code "${PAIR_CODE}")" || { err "PAIR_CODE is invalid."; return 1; }
  local rx="${parsed% *}" ry="${parsed#* }"
  if [[ "${ROLE}" == "source" ]]; then
    TUN_LOCAL_IP="10.${rx}.${ry}.1"; TUN_REMOTE_IP="10.${rx}.${ry}.2"
  else
    TUN_LOCAL_IP="10.${rx}.${ry}.2"; TUN_REMOTE_IP="10.${rx}.${ry}.1"
  fi
}

print_copy_block() {
  local src_ip dst_ip src_pubkey dst_pubkey
  if [[ "${ROLE}" == "source" ]]; then
    src_ip="${LOCAL_WAN_IP}"; dst_ip="${REMOTE_WAN_IP}"
    src_pubkey="${LOCAL_PUBKEY}"; dst_pubkey="${REMOTE_PUBKEY}"
  else
    src_ip="${REMOTE_WAN_IP}"; dst_ip="${LOCAL_WAN_IP}"
    src_pubkey="${REMOTE_PUBKEY}"; dst_pubkey="${LOCAL_PUBKEY}"
  fi

  echo "----- SIMPLE_WG_COPY_BLOCK -----"
  echo "PAIR_CODE=${PAIR_CODE}"
  echo "SOURCE_PUBLIC_IP=${src_ip}"
  echo "DEST_PUBLIC_IP=${dst_ip}"
  echo "SOURCE_PUBKEY=${src_pubkey}"
  echo "DEST_PUBKEY=${dst_pubkey}"
  echo "TUN_NAME=${TUN_NAME}"
  echo "ENDPOINT_PORT=${LISTEN_PORT}"
  echo "MTU=${MTU}"
  echo "----- END_COPY_BLOCK -----"
}

# FIX: این تابع فقط وقتی واقعاً بلاک paste شد success می‌دهد
prompt_paste_copy_block() {
  COPY_BLOCK_DETECTED=0

  echo -e "${CYA}Optional:${NC} Paste COPY BLOCK now (press Enter to skip)."
  echo -e "Finish paste by pressing ${WHT}Enter TWICE${NC} on empty lines."
  local first
  read -r -p "Paste the COPY BLOCK (or just Enter to skip): " first || true
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

  for kv in "${lines[@]}"; do
    [[ "$kv" =~ ^[A-Z0-9_]+= ]] || continue
    local key="${kv%%=*}" val="${kv#*=}"
    case "$key" in
      PAIR_CODE) PAIR_CODE="$val" ;;
      SOURCE_PUBLIC_IP) PASTE_SOURCE_PUBLIC_IP="$val" ;;
      DEST_PUBLIC_IP)   PASTE_DEST_PUBLIC_IP="$val" ;;
      SOURCE_PUBKEY)    PASTE_SOURCE_PUBKEY="$val" ;;
      DEST_PUBKEY)      PASTE_DEST_PUBKEY="$val" ;;
      TUN_NAME)         TUN_NAME="$val" ;;
      ENDPOINT_PORT)    LISTEN_PORT="$val" ;;
      MTU)              MTU="$val" ;;
    esac
  done

  [[ -n "${PAIR_CODE:-}" ]] && ! parse_pair_code "$PAIR_CODE" >/dev/null && { err "Pasted PAIR_CODE invalid."; return 1; }
  [[ -n "${PASTE_SOURCE_PUBLIC_IP:-}" ]] && ! is_ipv4 "$PASTE_SOURCE_PUBLIC_IP" && { err "Pasted SOURCE_PUBLIC_IP invalid."; return 1; }
  [[ -n "${PASTE_DEST_PUBLIC_IP:-}" ]] && ! is_ipv4 "$PASTE_DEST_PUBLIC_IP" && { err "Pasted DEST_PUBLIC_IP invalid."; return 1; }
  [[ -n "${PASTE_SOURCE_PUBKEY:-}" ]] && ! is_wg_key "$PASTE_SOURCE_PUBKEY" && { err "Pasted SOURCE_PUBKEY invalid."; return 1; }
  [[ -n "${PASTE_DEST_PUBKEY:-}" ]] && ! is_wg_key "$PASTE_DEST_PUBKEY" && { err "Pasted DEST_PUBKEY invalid."; return 1; }
  [[ -n "${TUN_NAME:-}" ]] && ! is_ifname "$TUN_NAME" && { err "Pasted TUN_NAME invalid."; return 1; }
  [[ -n "${LISTEN_PORT:-}" ]] && ! is_port "$LISTEN_PORT" && { err "Pasted ENDPOINT_PORT invalid."; return 1; }
  [[ -n "${MTU:-}" ]] && ! [[ "$MTU" =~ ^[0-9]+$ ]] && { err "Pasted MTU must be numeric."; return 1; }

  ok "COPY BLOCK parsed successfully."
  return 0
}

read_meta() {
  local f; f="$(conf_path_for "$1")"; [[ -f "$f" ]] || return 1
  ROLE=$(sed -n 's/^# ROLE=\(.*\)/\1/p' "$f" | head -n1)
  PAIR_CODE=$(sed -n 's/^# PAIR_CODE=\(.*\)/\1/p' "$f" | head -n1)
  LOCAL_WAN_IP=$(sed -n 's/^# LOCAL_WAN_IP=\(.*\)/\1/p' "$f" | head -n1)
  REMOTE_WAN_IP=$(sed -n 's/^# REMOTE_WAN_IP=\(.*\)/\1/p' "$f" | head -n1)
  REMOTE_PUBKEY=$(sed -n 's/^# REMOTE_PUBKEY=\(.*\)/\1/p' "$f" | head -n1)
  TUN_NAME="$1"

  # FIX: PrivateKey را از فایل می‌خوانیم (wg showconf برای فایل نیست)
  LOCAL_PRIVKEY=$(awk -F' = ' '/^[[:space:]]*PrivateKey[[:space:]]*=/{print $2; exit}' "$f" || true)
  [[ -n "${LOCAL_PRIVKEY:-}" ]] || { err "Could not read PrivateKey from $f"; return 1; }
  LOCAL_PUBKEY=$(echo "$LOCAL_PRIVKEY" | wg pubkey)

  LISTEN_PORT=$(awk -F' = ' '/^[[:space:]]*ListenPort[[:space:]]*=/{print $2; exit}' "$f" || true)
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

[Interface]
Address = ${TUN_LOCAL_IP}/30
PrivateKey = ${LOCAL_PRIVKEY}
ListenPort = ${LISTEN_PORT}
MTU = ${MTU}

[Peer]
PublicKey = ${REMOTE_PUBKEY}
AllowedIPs = ${TUN_REMOTE_IP}/32
Endpoint = ${REMOTE_WAN_IP}:${LISTEN_PORT}
PersistentKeepalive = 25
EOF
  chmod 600 "$f"
}

list_tunnels() {
  ensure_dirs; shopt -s nullglob
  for f in "$WG_DIR"/*.conf; do
    base="$(basename "$f")"; echo "${base%.conf}"
  done
  shopt -u nullglob
}

choose_tunnel() {
  local tunnels=(); while IFS= read -r t; do [[ -n "$t" ]] && tunnels+=("$t"); done < <(list_tunnels)
  ((${#tunnels[@]} == 0)) && { err "No tunnels found."; return 1; }
  echo -e "${MAG}Available tunnels:${NC}"
  local i
  for i in "${!tunnels[@]}"; do printf "  %s) %s\n" "$((i+1))" "${tunnels[$i]}"; done
  local choice
  while true; do
    read -r -p "Select tunnel [1-${#tunnels[@]}] (Enter=cancel): " choice || true
    [[ -z "${choice:-}" ]] && return 1
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#tunnels[@]} )); then
      SELECTED_TUN="${tunnels[$((choice-1))]}"; return 0
    fi
    err "Invalid selection."
  done
}

write_sysctl_persist() {
  ensure_dirs
  {
    echo "# Simple WireGuard sysctl (persist) - generated"
    echo "net.ipv4.ip_forward=1"
  } >"$SYSCTL_FILE"
  chmod 644 "$SYSCTL_FILE"
  sysctl --system >/dev/null 2>&1 || true
}

enable_service() { systemctl enable "$(service_for "$1")" >/dev/null 2>&1 || true; }
apply_now() { systemctl restart "$(service_for "$1")" >/dev/null 2>&1 || true; }
stop_disable_service() {
  systemctl stop "$(service_for "$1")" >/dev/null 2>&1 || true
  systemctl disable "$(service_for "$1")" >/dev/null 2>&1 || true
}

prompt_role() {
  echo "Select server role:"
  echo "  1) Source (Iran)"
  echo "  2) Destination (Kharej)"
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

prompt_tun_name_new() {
  local inp def; def="$(find_first_free_wg_name)"
  read -r -p "Tunnel interface name [${def}]: " inp || true
  inp="${inp:-$def}"
  is_ifname "$inp" || { err "Invalid interface name."; return 1; }
  tunnel_exists "$inp" && { err "Tunnel name '${inp}' is already taken."; return 1; }
  TUN_NAME="$inp"
}

prompt_wan_ips_keep() {
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

prompt_pair_code_keep() {
  local inp
  read -r -p "PAIR CODE [${PAIR_CODE:-auto}]: " inp || true
  if [[ -z "${inp:-}" ]]; then
    PAIR_CODE="$(generate_pair_code)"
    ok "Generated PAIR CODE: ${PAIR_CODE}"
  else
    parse_pair_code "$inp" >/dev/null || { err "Invalid PAIR CODE."; return 1; }
    PAIR_CODE="$inp"
  fi
}

prompt_details_keep() {
  local inp
  read -r -p "Listen Port [${LISTEN_PORT}]: " inp || true
  inp="${inp:-$LISTEN_PORT}"
  is_port "$inp" || { err "Invalid port."; return 1; }
  LISTEN_PORT="$inp"

  read -r -p "MTU [${MTU}]: " inp || true
  inp="${inp:-$MTU}"
  [[ "$inp" =~ ^[0-9]+$ ]] && (( inp >= 1280 && inp <= 1500 )) || { err "Invalid MTU."; return 1; }
  MTU="$inp"
}

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

  # Defaults
  MTU="1420"; LISTEN_PORT="51820"; PAIR_CODE=""
  LOCAL_WAN_IP=""; REMOTE_WAN_IP=""; LOCAL_PRIVKEY=""; LOCAL_PUBKEY=""
  REMOTE_PUBKEY=""; PASTE_SOURCE_PUBLIC_IP=""; PASTE_DEST_PUBLIC_IP=""
  PASTE_SOURCE_PUBKEY=""; PASTE_DEST_PUBKEY=""
  COPY_BLOCK_DETECTED=0

  if prompt_paste_copy_block; then
    ROLE="destination"
    log "COPY BLOCK detected. Assuming 'Destination' role."
  else
    prompt_role
  fi
  echo

  prompt_tun_name_new || return

  if (( COPY_BLOCK_DETECTED )); then
    # کاربر مقصد است: IP و کلید peer را از بلاک می‌گیرد
    LOCAL_WAN_IP="${PASTE_DEST_PUBLIC_IP}"
    REMOTE_WAN_IP="${PASTE_SOURCE_PUBLIC_IP}"
    REMOTE_PUBKEY="${PASTE_SOURCE_PUBKEY}"
    ok "Public IPs and Peer Key filled from COPY BLOCK."
  fi

  prompt_wan_ips_keep || return
  prompt_pair_code_keep || return
  recompute_tunnel_ips_from_pair || return
  prompt_details_keep || return

  log "Generating new keys for this server..."
  LOCAL_PRIVKEY=$(wg genkey)
  LOCAL_PUBKEY=$(echo "$LOCAL_PRIVKEY" | wg pubkey)
  ok "Local keys generated."

  if [[ -z "${REMOTE_PUBKEY:-}" ]]; then
    warn "You need the Public Key of the other server (the peer)."
    while ! is_wg_key "${REMOTE_PUBKEY:-}"; do
      read -r -p "Enter the Remote Peer's Public Key: " REMOTE_PUBKEY || true
    done
  fi

  write_conf "$TUN_NAME"
  write_sysctl_persist
  enable_service "$TUN_NAME"
  apply_now "$TUN_NAME"

  ok "Tunnel '${TUN_NAME}' created and started."
  echo
  show_info_one "$TUN_NAME"
}

do_edit() {
  choose_tunnel || return; local old_tun="$SELECTED_TUN"
  read_meta "$old_tun" || { err "Could not read config for $old_tun"; return; }
  log "Editing tunnel: $old_tun"; warn "Press Enter to keep current values."; echo

  local r; echo "Current role: ${ROLE}"; read -r -p "Change role? (1=Source, 2=Dest, Enter=keep): " r || true
  if [[ -n "${r:-}" ]]; then case "$r" in 1) ROLE="source";; 2) ROLE="destination";; esac; fi

  prompt_tun_name_keep || return
  prompt_wan_ips_keep || return
  prompt_pair_code_keep || return
  recompute_tunnel_ips_from_pair || return
  prompt_details_keep || return

  local inp; read -r -p "Remote Peer Public Key [${REMOTE_PUBKEY}]: " inp || true; inp="${inp:-$REMOTE_PUBKEY}"
  is_wg_key "$inp" || { err "Invalid remote public key."; return 1; }; REMOTE_PUBKEY="$inp"

  if [[ "$TUN_NAME" != "$old_tun" ]]; then
    warn "Tunnel name changed: $old_tun -> $TUN_NAME"; stop_disable_service "$old_tun"
    rm -f "$(conf_path_for "$old_tun")" || true
  fi

  write_conf "$TUN_NAME"; write_sysctl_persist; enable_service "$TUN_NAME"; apply_now "$TUN_NAME"
  ok "Tunnel '${TUN_NAME}' updated and applied."; echo; show_info_one "$TUN_NAME"
}

do_status_one() {
  choose_tunnel || return; local tun="$SELECTED_TUN"
  read_meta "$tun" || { err "Could not read config for $tun"; return; }
  echo -e "${MAG}===== WireGuard Status: ${tun} =====${NC}"
  echo -e "${WHT}Service:${NC}"; systemctl --no-pager --full status "$(service_for "$tun")" || true; echo
  echo -e "${WHT}Interface & Peer:${NC}"; wg show "$tun" || warn "Interface '$tun' is not active."; echo
  echo -e "${WHT}Connectivity:${NC} ping ${TUN_REMOTE_IP}"
  if ping -c 3 -W 2 "$TUN_REMOTE_IP" >/dev/null 2>&1; then
    ok "Ping successful. Tunnel is UP."
  else
    warn "Ping FAILED. Check firewall (UDP port ${LISTEN_PORT}) and keys."
  fi
}

do_status_all() {
  echo -e "${MAG}===== WireGuard Status: ALL TUNNELS =====${NC}"
  local tunnels; tunnels=$(list_tunnels); [[ -z "$tunnels" ]] && { warn "No tunnels configured."; return; }
  wg show all
}

show_info_one() {
  local tun_to_show="${1:-}"
  if [[ -z "$tun_to_show" ]]; then choose_tunnel || return; tun_to_show="$SELECTED_TUN"; fi
  read_meta "$tun_to_show" || { err "Could not read config for $tun_to_show"; return; }

  echo -e "${MAG}===== WireGuard Info: ${tun_to_show} =====${NC}"
  printf "%-22s %s\n" "Role:" "${ROLE}"
  printf "%-22s %s\n" "Pair Code:" "${PAIR_CODE}"
  printf "%-22s %s\n" "Tunnel Name:" "${TUN_NAME}"
  printf "%-22s %s\n" "Listen Port:" "${LISTEN_PORT}"
  printf "%-22s %s\n" "MTU:" "${MTU}"
  echo
  printf "%-22s %s\n" "Local Public IP:" "${LOCAL_WAN_IP}"
  printf "%-22s %s\n" "Local Tunnel IP:" "${TUN_LOCAL_IP}"
  printf "%-22s %s\n" "Local Public Key:" "${LOCAL_PUBKEY}"
  echo
  printf "%-22s %s\n" "Remote Public IP:" "${REMOTE_WAN_IP}"
  printf "%-22s %s\n" "Remote Tunnel IP:" "${TUN_REMOTE_IP}"
  printf "%-22s %s\n" "Remote Public Key:" "${REMOTE_PUBKEY}"
  echo
  echo -e "${CYA}COPY BLOCK (for other server):${NC}"
  print_copy_block
}

do_delete() {
  choose_tunnel || return; local tun="$SELECTED_TUN"
  warn "This will permanently delete tunnel '$tun' and its config file."
  local yn; read -r -p "Are you sure? [y/N]: " yn || true
  [[ ! "$yn" =~ ^([yY])$ ]] && { log "Canceled."; return; }
  stop_disable_service "$tun"; rm -f "$(conf_path_for "$tun")" || true
  ok "Deleted tunnel '$tun'."
}

banner() {
  echo -e "${MAG}========================================${NC}"
  echo -e "${WHT}  ${APP_NAME}${NC}"
  echo -e "${YEL}  Repo:${NC} ${BLU}${REPO_URL}${NC}"
  echo -e "${MAG}========================================${NC}"
}

menu() {
  while true; do
    clear || true; banner
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
      1) do_create; pause ;;
      2) do_edit; pause ;;
      3) do_status_one; pause ;;
      4) do_status_all; pause ;;
      5) show_info_one; pause ;;
      6) do_delete; pause ;;
      7) do_generate_keypair; pause ;;
      0) exit 0 ;;
      *) err "Invalid selection."; pause ;;
    esac
  done
}

main() {
  require_root
  require_cmds
  ensure_dirs
  menu
}

main "$@"
