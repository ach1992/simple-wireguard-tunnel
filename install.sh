#!/usr/bin/env bash
set -Eeuo pipefail

# ==================================================
# Simple WireGuard Tunnel Installer
# Repo: https://github.com/ach1992/simple-wireguard-tunnel
# ==================================================

REPO_RAW_BASE="https://raw.githubusercontent.com/ach1992/simple-wireguard-tunnel/main"
SCRIPT_NAME="wg_manager.sh"
INSTALL_PATH="/usr/local/bin/simple-wg"
TMP_DIR="/tmp/simple-wg-install.$$"

# Colors
RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"; NC="\033[0m"
log( )  { echo -e "${BLU}[INFO]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YEL}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Helper Functions ---
need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This installer must be run as root."
    err "Example (online):  curl -fsSL ${REPO_RAW_BASE}/install.sh | sudo bash"
    err "Example (local):   sudo bash install.sh"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

script_dir() {
  # Only safe when running from a real file (not from a pipe)
  local src="${BASH_SOURCE[0]}"
  while [ -h "$src" ]; do
    local dir; dir="$(cd -P "$(dirname "$src")" && pwd)"
    src="$(readlink "$src")"
    [[ "$src" != /* ]] && src="$dir/$src"
  done
  cd -P "$(dirname "$src")" && pwd
}

running_from_pipe() {
  # If stdin is NOT a terminal, usually it is piped: curl ... | bash
  [[ ! -t 0 ]]
}

wait_for_apt_lock() {
  # Wait until apt/dpkg locks are free (common on Ubuntu due to unattended-upgrades)
  local timeout="${1:-300}"  # seconds
  local interval=5
  local waited=0

  # These are common lock files on Debian/Ubuntu
  local locks=(
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/dpkg/lock"
    "/var/cache/apt/archives/lock"
  )

  while true; do
    local locked=0
    for lf in "${locks[@]}"; do
      if fuser "$lf" >/dev/null 2>&1; then
        locked=1
        break
      fi
    done

    if (( locked == 0 )); then
      return 0
    fi

    warn "apt/dpkg is locked (likely unattended-upgrades). Waiting..."
    sleep "$interval"
    waited=$((waited + interval))

    if (( waited >= timeout )); then
      err "apt/dpkg lock did not clear after ${timeout}s."
      err "Check running processes:"
      err "  ps aux | egrep 'apt|dpkg|unattended' | grep -v egrep"
      err "Or stop services safely:"
      err "  sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service"
      return 1
    fi
  done
}

apt_install() {
  # $@: packages
  export DEBIAN_FRONTEND=noninteractive
  wait_for_apt_lock 300 || return 1

  if ! apt-get update -y; then
    warn "apt-get update failed. Will try install anyway."
  fi

  wait_for_apt_lock 300 || return 1
  apt-get install -y "$@"
}

# --- Main Logic ---
install_deps() {
  if have_cmd wg && have_cmd wg-quick; then
    ok "wireguard-tools is already installed."
    return 0
  fi

  if ! have_cmd apt-get; then
    err "apt-get not found. Please install 'wireguard-tools' manually."
    err "Then re-run the installer."
    return 1
  fi

  warn "Installing missing dependency: wireguard-tools"
  if apt_install wireguard-tools; then
    ok "Dependency installed successfully."
  else
    err "Failed to install wireguard-tools."
    err "If apt is locked, wait for unattended-upgrades to finish, then retry."
    return 1
  fi
}

prepare_script() {
  mkdir -p "$TMP_DIR"

  if running_from_pipe; then
    # --- ONLINE MODE (from pipe) ---
    log "Installer is running from a pipe. Using online mode."
    if have_cmd curl; then
      log "Downloading latest manager script with curl..."
      curl -fsSL "${REPO_RAW_BASE}/${SCRIPT_NAME}" -o "${TMP_DIR}/${SCRIPT_NAME}"
    elif have_cmd wget; then
      log "Downloading latest manager script with wget..."
      wget -qO "${TMP_DIR}/${SCRIPT_NAME}" "${REPO_RAW_BASE}/${SCRIPT_NAME}"
    else
      err "curl or wget is required for online installation."
      exit 1
    fi
    ok "Downloaded ${SCRIPT_NAME} successfully."
    return 0
  fi

  # --- OFFLINE/LOCAL MODE ---
  local local_manager_path
  local_manager_path="$(script_dir)/${SCRIPT_NAME}"
  if [[ -f "$local_manager_path" ]]; then
    log "Local manager script found. Using offline mode."
    cp -f "$local_manager_path" "${TMP_DIR}/${SCRIPT_NAME}"
    return 0
  fi

  err "Local manager script (${SCRIPT_NAME}) not found in the same directory."
  err "Offline installation failed. Put install.sh and wg_manager.sh together."
  exit 1
}

install_script() {
  if [[ ! -s "${TMP_DIR}/${SCRIPT_NAME}" ]]; then
    err "Manager script is empty or not found. Cannot proceed with installation."
    exit 1
  fi

  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME}" "${INSTALL_PATH}"
  ok "Command installed successfully: ${INSTALL_PATH}"
}

post_check() {
  if command -v simple-wg >/dev/null 2>&1; then
    ok "simple-wg is available."
  else
    warn "simple-wg is not in PATH yet. Try opening a new shell."
  fi
}

main() {
  need_root
  install_deps || exit 1
  prepare_script
  install_script
  post_check

  echo
  ok "Installation completed."
  echo "You can now run the manager with:"
  echo -e "  ${GRN}sudo simple-wg${NC}"
}

main "$@"
