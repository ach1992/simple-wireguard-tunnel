
# Simple WireGuard Tunnel Manager

A simple, menu-driven Bash script to create and manage multiple **point-to-point WireGuard tunnels** between servers. Designed for Debian/Ubuntu and systemd.

---

## Features

- ✅ **Multiple Tunnels**: Manage several tunnels on one server, each connecting to a different peer.
- ✅ **Interactive Menu**: Create, Edit, Status, Info, and Delete tunnels easily.
- ✅ **Standard Integration**: Uses the standard `wg-quick@.service` for robust service management.
- ✅ **Auto-Configuration**:
    - Automatically generates a **PAIR CODE** (`10.X.Y`) for a clean `/30` tunnel IP plan.
    - Generates **Private/Public keys** for each server.
    - Creates a **COPY BLOCK** to quickly configure the peer server.
- ✅ **Painless Setup**: The "COPY BLOCK" workflow makes setting up the second server trivial and error-free.
- ✅ **System Ready**: Automatically enables IPv4 forwarding and persists the setting.

---

## Requirements

- Two servers running **Debian or Ubuntu**.
- **Root access** on both servers.
- A **public IPv4 address** on each server.
- **UDP port** (default: 51820) must be open between the servers.

---

## Install & Run

### 1. Online Install & Run (Recommended)

Download and run the installer with one command. This ensures you get the latest version.

```bash
curl -fsSL https://raw.githubusercontent.com/ach1992/simple-wireguard-tunnel/main/install.sh | sudo bash
sudo simple-wg
```

### 2. Offline Install

If you have the script files locally, you can install without an internet connection.

**Folder Structure:**
```plaintext
simple-wireguard-tunnel/
├─ install.sh
└─ wg_manager.sh
```

**Install:**

```bash
# Navigate to the directory containing the files
cd simple-wireguard-tunnel/

# Run the installer
sudo bash install.sh
```

After installation, run the manager:

```bash
sudo simple-wg
```

---

## How It Works: A Quick Workflow

### Step 1: On the First Server (e.g., "Source")
Run the manager:

```bash
sudo simple-wg
```

Select 1) Create tunnel.  
Choose 1) Source (Iran).  
Follow the prompts (press Enter to accept defaults for name, port, etc.).  
The script will generate keys and display a COPY BLOCK. Copy this entire block.

Example COPY BLOCK:
```plaintext
----- SIMPLE_WG_COPY_BLOCK -----
PAIR_CODE=10.100.50
SOURCE_PUBLIC_IP=1.2.3.4
DEST_PUBLIC_IP=5.6.7.8
SOURCE_PUBKEY=abc...xyz=
DEST_PUBKEY=123...789=
TUN_NAME=wg1
LISTEN_PORT=51820
MTU=1420
----- END_COPY_BLOCK -----
```

### Step 2: On the Second Server (e.g., "Destination")
Run the manager:

```bash
sudo simple-wg
```

Select 1) Create tunnel.  
Choose 2) Destination (Kharej).  
When prompted, paste the COPY BLOCK you copied from the first server.  
Press Enter twice on empty lines to confirm the paste.  
The script will automatically fill in all the necessary details.  

That's it! The tunnel is now configured and active on both servers.

---

## Menu Options

1) **Create tunnel**: Guides you through creating a new WireGuard tunnel.  
2) **Edit tunnel**: Allows you to modify an existing tunnel's configuration (e.g., change IPs, port, or peer key).  
3) **Status (one tunnel)**: Shows detailed status for a single tunnel, including the systemd service status, interface details, and a live ping test.  
4) **Status (all tunnels)**: Provides a quick overview of all active WireGuard interfaces using `wg show all`.  
5) **Info / COPY BLOCK**: Displays the full configuration details and the COPY BLOCK for a selected tunnel.  
6) **Delete tunnel**: Permanently removes a tunnel's configuration file and disables its service.  
0) **Exit**: Exits the script.

---

## Files & Services

**Main Command**: /usr/local/bin/simple-wg  
**Configuration Files**: /etc/wireguard/<TUN_NAME>.conf (e.g., /etc/wireguard/wg1.conf)  
**Systemd Service**: wg-quick@<TUN_NAME>.service (e.g., wg-quick@wg1.service)  
**Sysctl for Forwarding**: /etc/simple-wireguard/99-simple-wireguard.conf

---

## How to Verify the Tunnel

The easiest way is to use the Status (one tunnel) option in the menu, which runs a ping test for you.  
Alternatively, you can manually ping the remote tunnel IP from each server.

From the Source server:

```bash
ping 10.X.Y.2
```

From the Destination server:

```bash
ping 10.X.Y.1
```

You can also check the interface status directly (replace `wg1` with your tunnel name):

```bash
# Show live peer information (handshake, etc.)
wg show wg1

# Check IP address
ip addr show wg1
```

---

## Troubleshooting

**Ping Fails / No Handshake**:  
- **Firewall**: Ensure the UDP port (e.g., 51820) is allowed on both servers.  
- **Public Keys**: Double-check that the public key of each server is correctly configured on the other. The Info menu can help verify this.  
- **Endpoint IP**: Make sure the public IP address (Endpoint) in the config file is correct and reachable.  

**MTU Issues**:  
If you experience packet loss or slow speeds with large transfers, the MTU might be too high. The default is 1420, which is generally safe. You can try lowering it to 1380 or 1280 via the Edit tunnel menu if problems persist.

---

## License

This project is licensed under the MIT License.
