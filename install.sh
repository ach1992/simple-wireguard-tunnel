#!/usr/bin/env bash
set -Eeuo pipefail

# ==================================================
# Simple WireGuard Tunnel Installer
# Repo: https://github.com/ach1992/simple-wireguard-tunnel
#
# Online usage:
#   curl -fsSL https://.../install.sh | sudo bash
#
# Offline usage:
#   sudo bash install.sh
# ==================================================

REPO_RAW_BASE="https://raw.githubusercontent.com/ach1992/simple-wireguard-tunnel/main"
SCRIPT_NAME="wg_manager.sh"
INSTALL_PATH="/usr/local/bin/simple-wg"
TMP_DIR="/tmp/simple-wg-install.$$"

RED="\033[0;31m"; GRN="\033[0;32m"; YEL="\033[0;33m"; BLU="\033[0;34m"; NC="\033[0m"
log( )  { echo -e "${BLU}[INFO]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YEL}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This installer must be run as root. Example: sudo bash install.sh"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

script_dir() {
  local src="${BASH_SOURCE[0]}"
  while [ -h "$src" ]; do
    local dir; dir="$(cd -P "$(dirname "$src")" && pwd)"
    src="$(readlink "$src")"; [[ "$src" != /* ]] && src="$dir/$src"
  done
  cd -P "$(dirname "$src")" && pwd
}

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
  apt-get update -y
  if apt-get install -y wireguard-tools; then
    ok "Dependency installed successfully."
  else
    err "Failed to install wireguard-tools. Please install it manually."
    return 1
  fi
}

prepare_script() {
  mkdir -p "$TMP_DIR"
  local local_path="${script_dir}/${SCRIPT_NAME}"

  if [[ -f "$local_path" ]]; then
    log "Using local ${SCRIPT_NAME} (offline mode)."
    cp -f "$local_path" "${TMP_DIR}/${SCRIPT_NAME}"
    return 0
  fi

  if [[ -f "${BASH_SOURCE[0]}" ]]; then
      err "Local ${SCRIPT_NAME} not found. Offline installation is not possible."
      exit 1
  fi

  log "Installer running from stdin. Downloading latest script..."
  if ! have_cmd curl; then
    err "curl is required for online installation."
    exit 1
  fi
  curl -fsSL "${REPO_RAW_BASE}/${SCRIPT_NAME}" -o "${TMP_DIR}/${SCRIPT_NAME}"
  ok "Downloaded latest ${SCRIPT_NAME}."
}

install_script() {
  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME}" "${INSTALL_PATH}"
  ok "Command installed: simple-wg"
}

cleanup() { rm -rf "$TMP_DIR" >/dev/null 2>&1 || true; }

main() {
  trap cleanup EXIT
  need_root
  install_deps || exit 1
  prepare_script
  install_script

  echo
  ok "Installation completed successfully."
  echo "Run:"
  echo "  sudo simple-wg"
}

main "$@"
