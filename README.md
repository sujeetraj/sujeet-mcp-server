# Kali Linux MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Kali Linux security tools as callable tools for any MCP-compatible AI client — Claude Desktop, Claude Code CLI, Cursor, Continue, or any custom MCP client.

> **Legal notice:** Use only against systems you own or have explicit written authorization to test. Unauthorized scanning or exploitation is illegal.

---

## Features

| Tool | Description |
|---|---|
| `system_info` | OS, kernel, user, network interfaces |
| `nmap_scan` | Port & service scanning |
| `nikto_scan` | Web vulnerability scanning |
| `gobuster_scan` | Directory & file enumeration |
| `sqlmap_scan` | SQL injection testing |
| `whois_lookup` | WHOIS for domain / IP |
| `dns_lookup` | DNS records via `dig` |
| `ping_host` | ICMP reachability check |
| `hash_identify` | Identify hash type via `hashid` |
| `list_installed_tools` | Check which Kali tools are installed |
| `netstat_info` | Connections, listening ports, routes |
| `run_shell_command` | Run arbitrary commands (dangerous ones blocked) |

---

## Transport modes

The server supports two transports so it works with **any MCP client**:

| Mode | Flag | Use case |
|---|---|---|
| **stdio** | *(default)* | Claude Code CLI, Cursor, Continue — client spawns the process |
| **SSE / HTTP** | `--sse` | Claude Desktop, remote clients, systemd service |

---

## Requirements

- Kali Linux (or any Debian-based Linux with security tools installed)
- Python 3.10+

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/sujeetraj/sujeet-mcp-server.git
cd sujeet-mcp-server
```

### 2. Install dependencies

Kali Linux (Python 3.13+) blocks system-wide pip installs. Use a venv instead:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### stdio mode (for CLI clients)

The client spawns the server process directly over stdin/stdout. No extra setup needed.

```bash
# with venv active
python3 kali_mcp_server.py

# or full path without activating
venv/bin/python3 kali_mcp_server.py
```

### SSE / HTTP mode (for remote or Desktop clients)

```bash
# with venv active
python3 kali_mcp_server.py --sse --host 0.0.0.0 --port 8765

# or full path
venv/bin/python3 kali_mcp_server.py --sse --host 0.0.0.0 --port 8765
```

The server will be reachable at `http://<your-kali-ip>:8765/sse`.

---

## Run as a systemd service (auto-start on boot)

Use the included setup script — **run as root**:

```bash
sudo bash setup.sh
```

This will:
1. Install Python dependencies system-wide
2. Copy the server to `/opt/kali-mcp-server/`
3. Write and enable a systemd unit (`kali-mcp-server.service`)
4. Start the service immediately

Useful service commands:

```bash
systemctl status kali-mcp-server     # check status
journalctl -u kali-mcp-server -f     # live logs
systemctl stop kali-mcp-server       # stop
systemctl disable kali-mcp-server    # disable auto-start
```

---

## Client configuration

### Claude Code CLI

```bash
# stdio mode (recommended for local use)
claude mcp add kali-mcp-server python3 /path/to/kali_mcp_server.py

# SSE mode (if the service is running)
claude mcp add kali-mcp-server --transport sse http://<KALI-IP>:8765/sse
```

### Claude Desktop

Edit `~/.config/Claude/claude_desktop_config.json` (Linux/macOS):

**stdio mode** (server on the same machine):
```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "command": "python3",
      "args": ["/path/to/kali_mcp_server.py"]
    }
  }
}
```

**SSE mode** (server running as a service, possibly on a remote Kali VM):
```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "url": "http://<KALI-IP>:8765/sse"
    }
  }
}
```

### Cursor / Continue / other MCP clients

These clients support either stdio or SSE. Use the stdio config if the client is on the same machine, or the SSE URL if connecting remotely. Refer to your client's MCP documentation for the exact config format.

---

## Security considerations

- The `run_shell_command` tool blocks a list of destructive patterns (`rm -rf`, `shutdown`, `mkfs`, etc.) but is not a full sandbox. Restrict access to trusted users.
- In SSE mode, the server binds to `0.0.0.0` by default. Use a firewall rule or bind to `127.0.0.1` if you only need local access:
  ```bash
  python3 kali_mcp_server.py --sse --host 127.0.0.1 --port 8765
  ```
- The systemd service runs as your user (not root) and sets `NoNewPrivileges=true` and `PrivateTmp=true`.

---

## Project structure

```
sujeet-mcp-server/
├── kali_mcp_server.py          # MCP server (stdio + SSE)
├── kali-mcp-server.service     # systemd unit file (reference)
├── setup.sh                    # install + service registration script
├── requirements.txt            # Python dependencies
└── claude_desktop_config.json  # Claude Desktop config template
```

---

## License

MIT
