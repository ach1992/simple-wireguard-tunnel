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
    err "This installer must be run as root. Example: sudo bash install.sh"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

script_dir() {
  # This function is only safe to call when not running from a pipe.
  local src="${BASH_SOURCE[0]}"
  while [ -h "$src" ]; do
    local dir; dir="$(cd -P "$(dirname "$src")" && pwd)"
    src="$(readlink "$src")"; [[ "$src" != /* ]] && src="$dir/$src"
  done
  cd -P "$(dirname "$src")" && pwd
}

# --- Main Logic ---
install_deps() {
  if have_cmd wg && have_cmd wg-quick; then
    ok "wireguard-tools is already installed."
    return 0
  fi

  if ! have_cmd apt-get; then
    err "apt-get not found. Please install 'wireguard-tools' manually."
    return 1
  fi

  warn "Installing missing dependency: wireguard-tools"
  export DEBIAN_FRONTEND=noninteractive
  if ! apt-get update -y; then
      warn "apt-get update failed. Trying to proceed with installation anyway."
  fi
  
  if apt-get install -y wireguard-tools; then
    ok "Dependency installed successfully."
  else
    err "Failed to install wireguard-tools. Please install it manually and re-run."
    return 1
  fi
}

prepare_script() {
  mkdir -p "$TMP_DIR"
  
  # Check if running from a file on disk. /dev/stdin is a pipe, not a file.
  if [[ -f "${BASH_SOURCE[0]:-}" ]]; then
    # --- OFFLINE/LOCAL MODE ---
    local local_manager_path
    local_manager_path="$(script_dir)/${SCRIPT_NAME}"

    if [[ -f "$local_manager_path" ]]; then
      log "Local manager script found. Using offline mode."
      cp -f "$local_manager_path" "${TMP_DIR}/${SCRIPT_NAME}"
      return 0
    else
      err "Local manager script (${SCRIPT_NAME}) not found in the same directory."
      err "Offline installation failed. Please place both install.sh and wg_manager.sh together."
      exit 1
    fi
  else
    # --- ONLINE MODE (from pipe) ---
    log "Installer is running from a pipe. Using online mode."
    if ! have_cmd curl; then
      err "curl is required for online installation."
      exit 1
    fi
    log "Downloading latest manager script..."
    curl -fsSL "${REPO_RAW_BASE}/${SCRIPT_NAME}" -o "${TMP_DIR}/${SCRIPT_NAME}"
    ok "Downloaded ${SCRIPT_NAME} successfully."
    return 0
  fi
}

install_script() {
  if [[ ! -s "${TMP_DIR}/${SCRIPT_NAME}" ]]; then
      err "Manager script is empty or not found. Cannot proceed with installation."
      exit 1
  fi
  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME}" "${INSTALL_PATH}"
  ok "Command installed successfully: ${INSTALL_PATH}"
}

main() {
  need_root
  install_deps || exit 1
  prepare_script
  install_script

  echo
  ok "Installation completed."
  echo "You can now run the manager with the command:"
  echo -e "  ${GRN}sudo simple-wg${NC}"
}

main "$@"
