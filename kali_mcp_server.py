#!/usr/bin/env python3
"""
Kali Linux MCP Server
Exposes Kali Linux security tools as MCP tools for any MCP-compatible client.
Intended for authorized penetration testing and security research only.

Usage:
  python3 kali_mcp_server.py                        # stdio (Claude Code CLI, Cursor, etc.)
  python3 kali_mcp_server.py --http                 # HTTP on 0.0.0.0:8765  (LM Studio, Claude Desktop, etc.)
  python3 kali_mcp_server.py --http --host 127.0.0.1 --port 9000
"""

import argparse
import subprocess
import shutil
import sys
from typing import Optional
from mcp.server.fastmcp import FastMCP

# ── server instance ───────────────────────────────────────────────────────────
mcp = FastMCP(
    name="kali-mcp-server",
    instructions=(
        "Kali Linux MCP Server. Provides security testing tools including "
        "nmap, nikto, gobuster, sqlmap, whois, dig, and more. "
        "Use only against systems you are authorized to test."
    ),
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 120) -> str:
    """Run a shell command and return combined output string."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        parts = []
        if r.stdout.strip():
            parts.append(r.stdout.strip())
        if r.stderr.strip():
            parts.append(f"[stderr]\n{r.stderr.strip()}")
        return "\n".join(parts) if parts else f"(no output, exit code {r.returncode})"
    except subprocess.TimeoutExpired:
        return f"[timeout] Command exceeded {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return f"[not found] {cmd[0]} is not installed on this system."
    except Exception as e:
        return f"[error] {e}"


# ── tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def system_info() -> str:
    """Get system information: OS, kernel, hostname, current user, and network interfaces."""
    sections = [
        ("Kernel",             ["uname", "-a"]),
        ("Hostname",           ["hostname"]),
        ("User",               ["whoami"]),
        ("ID",                 ["id"]),
        ("Network Interfaces", ["ip", "addr", "show"]),
    ]
    return "\n\n".join(f"[{label}]\n{_run(cmd)}" for label, cmd in sections)


@mcp.tool()
def nmap_scan(target: str, options: str = "-sV") -> str:
    """
    Run an nmap scan against a target host, IP, or CIDR range.
    Only use against systems you are authorized to test.

    Args:
        target:  IP address, hostname, or CIDR (e.g. 192.168.1.1 or 192.168.1.0/24)
        options: nmap flags (e.g. '-sV -sC -p 80,443 -A'). Default: '-sV'
    """
    cmd = ["nmap"] + options.split() + [target]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def nikto_scan(target: str, port: Optional[int] = None) -> str:
    """
    Run a Nikto web vulnerability scan against a target.
    Only use against systems you are authorized to test.

    Args:
        target: Target URL or IP (e.g. http://192.168.1.10 or 192.168.1.10)
        port:   Target port (optional, default 80)
    """
    cmd = ["nikto", "-h", target]
    if port:
        cmd += ["-p", str(port)]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def gobuster_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: Optional[str] = None,
) -> str:
    """
    Run Gobuster directory/file enumeration on a web server.

    Args:
        url:        Target URL (e.g. http://192.168.1.10)
        wordlist:   Path to wordlist (default: /usr/share/wordlists/dirb/common.txt)
        extensions: File extensions to search, comma-separated (e.g. 'php,html,txt')
    """
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist]
    if extensions:
        cmd += ["-x", extensions]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def sqlmap_scan(url: str, options: str = "--batch --level=1 --risk=1") -> str:
    """
    Run sqlmap to test for SQL injection vulnerabilities.
    Only use against systems you are authorized to test.

    Args:
        url:     Target URL with parameter (e.g. 'http://site.com/page?id=1')
        options: Additional sqlmap options (default: '--batch --level=1 --risk=1')
    """
    cmd = ["sqlmap", "-u", url] + options.split()
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def whois_lookup(target: str) -> str:
    """
    Perform a WHOIS lookup for a domain or IP address.

    Args:
        target: Domain name or IP address
    """
    return _run(["whois", target], timeout=30)


@mcp.tool()
def dns_lookup(target: str, record_type: str = "ANY") -> str:
    """
    Perform a DNS lookup using dig.

    Args:
        target:      Domain name or IP address
        record_type: DNS record type — A, AAAA, MX, NS, TXT, CNAME, SOA, ANY (default: ANY)
    """
    cmd = ["dig", target, record_type, "+noall", "+answer", "+authority"]
    result = _run(cmd, timeout=30)
    if not result.strip() or result.startswith("["):
        # fallback: full dig output
        result = _run(["dig", target, record_type], timeout=30)
    return result


@mcp.tool()
def ping_host(target: str, count: int = 4) -> str:
    """
    Ping a host to check network connectivity.

    Args:
        target: Hostname or IP address
        count:  Number of ICMP packets to send (default: 4)
    """
    return _run(["ping", "-c", str(count), target], timeout=30)


@mcp.tool()
def hash_identify(hash_value: str) -> str:
    """
    Identify the type of a hash string using hashid.

    Args:
        hash_value: The hash string to identify (e.g. 5f4dcc3b5aa765d61d8327deb882cf99)
    """
    if shutil.which("hashid"):
        return _run(["hashid", hash_value])
    elif shutil.which("hash-identifier"):
        try:
            r = subprocess.run(
                ["hash-identifier"],
                input=hash_value + "\n\n",
                capture_output=True,
                text=True,
                timeout=10,
            )
            return r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            return f"[error] {e}"
    return "hashid is not installed. Run: sudo apt install hashid"


@mcp.tool()
def list_installed_tools() -> str:
    """List common Kali Linux security tools and show whether each is installed."""
    tools = [
        "nmap", "nikto", "gobuster", "sqlmap", "msfconsole",
        "hydra", "john", "hashcat", "aircrack-ng", "wireshark",
        "dirb", "wfuzz", "whatweb", "dnsenum", "fierce",
        "theHarvester", "netcat", "socat", "hashid",
        "binwalk", "volatility3", "autopsy",
    ]
    lines = [f"  {'✓' if shutil.which(t) else '✗'}  {t}" for t in tools]
    return "Kali Linux Tool Status:\n" + "\n".join(lines)


@mcp.tool()
def netstat_info(mode: str = "listening") -> str:
    """
    Show network connection information.

    Args:
        mode: 'listening' (open ports), 'connections' (active sessions), 'routes' (routing table)
    """
    if mode == "connections":
        cmd = ["ss", "-tunp"]
    elif mode == "routes":
        cmd = ["ip", "route", "show"]
    else:
        cmd = ["ss", "-tlnp"]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=15)}"


@mcp.tool()
def run_shell_command(command: str, timeout: int = 60) -> str:
    """
    Run an arbitrary shell command on the Kali Linux machine.
    Clearly destructive patterns are blocked. USE ONLY FOR AUTHORIZED TESTING.

    Args:
        command: Shell command to execute
        timeout: Timeout in seconds, max 300 (default: 60)
    """
    BLOCKED = ["rm -rf", "rm -f /", "shutdown", "reboot", "halt",
               "poweroff", "mkfs", "dd if=", ":(){:|:&};:"]
    for pattern in BLOCKED:
        if pattern in command.lower():
            return f"[blocked] Command contains dangerous pattern: '{pattern}'"

    timeout = min(int(timeout), 300)
    return f"$ {command}\n\n{_run(['bash', '-c', command], timeout=timeout)}"


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali Linux MCP Server")
    parser.add_argument(
        "--http", action="store_true",
        help="Run in HTTP mode — serves both Streamable HTTP (/mcp) and legacy SSE (/sse). "
             "Use this for LM Studio, Claude Desktop, or any remote MCP client.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    args = parser.parse_args()

    if args.http:
        try:
            import uvicorn
        except ImportError:
            print("HTTP mode requires uvicorn: pip install uvicorn starlette", file=sys.stderr)
            sys.exit(1)

        print(f"Kali MCP Server (HTTP) → http://{args.host}:{args.port}/sse", file=sys.stderr)
        print(f"                         http://{args.host}:{args.port}/mcp  (Streamable HTTP)", file=sys.stderr)

        # FastMCP exposes a Starlette app that handles BOTH:
        #   GET  /sse          → legacy SSE stream (LM Studio fallback, Claude Desktop)
        #   POST /messages/    → legacy SSE messages
        #   POST /mcp          → Streamable HTTP (new spec, LM Studio primary)
        #   GET  /mcp          → Streamable HTTP SSE upgrade
        app = mcp.get_app()
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    else:
        # stdio mode — client (Claude Code CLI, Cursor, Continue…) spawns this process
        mcp.run(transport="stdio")
