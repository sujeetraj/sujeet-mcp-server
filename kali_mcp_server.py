#!/usr/bin/env python3
"""
Kali Linux MCP Server
Exposes common Kali Linux security tools as MCP tools for use with Claude.
Intended for authorized penetration testing and security research only.

Usage:
  python3 kali_mcp_server.py                  # stdio mode (default, for CLI)
  python3 kali_mcp_server.py --sse            # SSE/HTTP mode on 0.0.0.0:8765
  python3 kali_mcp_server.py --sse --host 127.0.0.1 --port 9000
"""

import argparse
import asyncio
import subprocess
import shutil
import sys
from typing import Any
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp import types

server = Server("kali-mcp-server")


def run_command(cmd: list[str], timeout: int = 120) -> dict[str, Any]:
    """Run a shell command and return stdout, stderr, and return code."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def format_result(result: dict[str, Any]) -> str:
    parts = []
    if result["stdout"]:
        parts.append(result["stdout"].strip())
    if result["stderr"]:
        parts.append(f"[stderr]\n{result['stderr'].strip()}")
    if not parts:
        parts.append(f"(no output, exit code {result['returncode']})")
    return "\n".join(parts)


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="system_info",
            description="Get system information: OS, kernel, hostname, current user, network interfaces.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="nmap_scan",
            description=(
                "Run an nmap scan against a target. "
                "Only use against systems you are authorized to test."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address, hostname, or CIDR range (e.g. 192.168.1.1, 192.168.1.0/24)",
                    },
                    "options": {
                        "type": "string",
                        "description": "Additional nmap flags (e.g. '-sV -sC -p 80,443 -A'). Defaults to '-sV'.",
                        "default": "-sV",
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="nikto_scan",
            description=(
                "Run a Nikto web vulnerability scan against a target URL. "
                "Only use against systems you are authorized to test."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or IP (e.g. http://192.168.1.10 or 192.168.1.10)",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Target port (optional, default 80).",
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="gobuster_scan",
            description=(
                "Run Gobuster for directory/file enumeration on a web server. "
                "Requires a wordlist on the Kali machine."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g. http://192.168.1.10)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file.",
                        "default": "/usr/share/wordlists/dirb/common.txt",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "File extensions to search (e.g. 'php,html,txt').",
                    },
                },
                "required": ["url"],
            },
        ),
        types.Tool(
            name="sqlmap_scan",
            description=(
                "Run sqlmap to test for SQL injection vulnerabilities. "
                "Only use against systems you are authorized to test."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with parameter (e.g. 'http://site.com/page?id=1')",
                    },
                    "options": {
                        "type": "string",
                        "description": "Additional sqlmap options (e.g. '--dbs --batch').",
                        "default": "--batch --level=1 --risk=1",
                    },
                },
                "required": ["url"],
            },
        ),
        types.Tool(
            name="whois_lookup",
            description="Perform a WHOIS lookup for a domain or IP address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain or IP address."},
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="dns_lookup",
            description="Perform DNS enumeration/lookup using dig or nslookup.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain name or IP address."},
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY.",
                        "default": "ANY",
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="ping_host",
            description="Ping a host to check connectivity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname or IP address."},
                    "count": {
                        "type": "integer",
                        "description": "Number of ping packets (default 4).",
                        "default": 4,
                    },
                },
                "required": ["target"],
            },
        ),
        types.Tool(
            name="hash_identify",
            description="Identify the type of a hash string using hashid or hash-identifier.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "The hash string to identify."},
                },
                "required": ["hash"],
            },
        ),
        types.Tool(
            name="list_installed_tools",
            description="List common Kali Linux security tools and whether they are installed.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="netstat_info",
            description="Show active network connections, listening ports, and routing info.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "description": "'connections' (active connections), 'listening' (open ports), 'routes' (routing table).",
                        "default": "listening",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="run_shell_command",
            description=(
                "Run an arbitrary shell command on the Kali Linux machine. "
                "USE ONLY FOR AUTHORIZED TESTING. Dangerous commands (rm, shutdown, etc.) are blocked."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to run.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (max 300, default 60).",
                        "default": 60,
                    },
                },
                "required": ["command"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:

    def text(content: str) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=content)]

    # ── system_info ──────────────────────────────────────────────────────────
    if name == "system_info":
        parts = []
        for cmd, label in [
            (["uname", "-a"], "Kernel"),
            (["hostname"], "Hostname"),
            (["whoami"], "User"),
            (["id"], "ID"),
            (["ip", "addr", "show"], "Network Interfaces"),
        ]:
            r = run_command(cmd)
            parts.append(f"[{label}]\n{format_result(r)}")
        return text("\n\n".join(parts))

    # ── nmap_scan ─────────────────────────────────────────────────────────────
    if name == "nmap_scan":
        target = arguments["target"]
        options = arguments.get("options", "-sV")
        cmd = ["nmap"] + options.split() + [target]
        r = run_command(cmd, timeout=300)
        return text(f"$ {' '.join(cmd)}\n\n{format_result(r)}")

    # ── nikto_scan ────────────────────────────────────────────────────────────
    if name == "nikto_scan":
        target = arguments["target"]
        cmd = ["nikto", "-h", target]
        if "port" in arguments:
            cmd += ["-p", str(arguments["port"])]
        r = run_command(cmd, timeout=300)
        return text(f"$ {' '.join(cmd)}\n\n{format_result(r)}")

    # ── gobuster_scan ─────────────────────────────────────────────────────────
    if name == "gobuster_scan":
        url = arguments["url"]
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist]
        if "extensions" in arguments:
            cmd += ["-x", arguments["extensions"]]
        r = run_command(cmd, timeout=300)
        return text(f"$ {' '.join(cmd)}\n\n{format_result(r)}")

    # ── sqlmap_scan ───────────────────────────────────────────────────────────
    if name == "sqlmap_scan":
        url = arguments["url"]
        options = arguments.get("options", "--batch --level=1 --risk=1")
        cmd = ["sqlmap", "-u", url] + options.split()
        r = run_command(cmd, timeout=300)
        return text(f"$ {' '.join(cmd)}\n\n{format_result(r)}")

    # ── whois_lookup ──────────────────────────────────────────────────────────
    if name == "whois_lookup":
        r = run_command(["whois", arguments["target"]], timeout=30)
        return text(format_result(r))

    # ── dns_lookup ────────────────────────────────────────────────────────────
    if name == "dns_lookup":
        target = arguments["target"]
        record_type = arguments.get("record_type", "ANY")
        r = run_command(["dig", target, record_type, "+noall", "+answer", "+authority"], timeout=30)
        if not r["stdout"].strip():
            # fallback to full dig output
            r = run_command(["dig", target, record_type], timeout=30)
        return text(format_result(r))

    # ── ping_host ─────────────────────────────────────────────────────────────
    if name == "ping_host":
        target = arguments["target"]
        count = str(arguments.get("count", 4))
        r = run_command(["ping", "-c", count, target], timeout=30)
        return text(format_result(r))

    # ── hash_identify ─────────────────────────────────────────────────────────
    if name == "hash_identify":
        hash_val = arguments["hash"]
        if shutil.which("hashid"):
            r = run_command(["hashid", hash_val])
        elif shutil.which("hash-identifier"):
            # hash-identifier reads from stdin
            try:
                result = subprocess.run(
                    ["hash-identifier"],
                    input=hash_val + "\n\n",
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return text(result.stdout.strip() or result.stderr.strip())
            except Exception as e:
                return text(f"Error: {e}")
        else:
            return text("Neither 'hashid' nor 'hash-identifier' is installed. Run: sudo apt install hashid")
        return text(format_result(r))

    # ── list_installed_tools ──────────────────────────────────────────────────
    if name == "list_installed_tools":
        tools = [
            "nmap", "nikto", "gobuster", "sqlmap", "metasploit-framework",
            "hydra", "john", "hashcat", "aircrack-ng", "wireshark",
            "burpsuite", "dirb", "wfuzz", "whatweb", "dnsenum",
            "fierce", "theHarvester", "maltego", "netcat", "socat",
            "hashid", "binwalk", "volatility3", "autopsy",
        ]
        lines = []
        for tool in tools:
            binary = tool.replace("-framework", "").lower()
            installed = "✓" if shutil.which(binary) else "✗"
            lines.append(f"  {installed}  {tool}")
        return text("Kali Linux Tool Status:\n" + "\n".join(lines))

    # ── netstat_info ──────────────────────────────────────────────────────────
    if name == "netstat_info":
        mode = arguments.get("mode", "listening")
        if mode == "connections":
            cmd = ["ss", "-tunp"]
        elif mode == "routes":
            cmd = ["ip", "route", "show"]
        else:  # listening
            cmd = ["ss", "-tlnp"]
        r = run_command(cmd, timeout=15)
        return text(f"$ {' '.join(cmd)}\n\n{format_result(r)}")

    # ── run_shell_command ─────────────────────────────────────────────────────
    if name == "run_shell_command":
        command = arguments["command"]
        timeout = min(int(arguments.get("timeout", 60)), 300)

        # Block clearly destructive commands
        blocked_prefixes = ["rm -rf", "rm -f /", "shutdown", "reboot", "halt",
                            "poweroff", "mkfs", "dd if=", ":(){:|:&};:"]
        for prefix in blocked_prefixes:
            if prefix in command.lower():
                return text(f"Blocked: command contains dangerous pattern '{prefix}'.")

        r = run_command(["bash", "-c", command], timeout=timeout)
        return text(f"$ {command}\n\n{format_result(r)}")

    return text(f"Unknown tool: {name}")


def get_init_options() -> InitializationOptions:
    return InitializationOptions(
        server_name="kali-mcp-server",
        server_version="1.0.0",
        capabilities=server.get_capabilities(
            notification_options=None,
            experimental_capabilities={},
        ),
    )


async def run_stdio():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, get_init_options())


async def run_sse(host: str, port: int):
    try:
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Route, Mount
        import uvicorn
    except ImportError:
        print(
            "SSE mode requires extra packages. Install them with:\n"
            "  pip3 install --user 'mcp[cli]' uvicorn starlette",
            file=sys.stderr,
        )
        sys.exit(1)

    sse_transport = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await server.run(read_stream, write_stream, get_init_options())

    starlette_app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ]
    )

    print(f"Kali MCP Server listening on http://{host}:{port}/sse", file=sys.stderr)
    config = uvicorn.Config(starlette_app, host=host, port=port, log_level="info")
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali Linux MCP Server")
    parser.add_argument("--sse", action="store_true", help="Run in SSE/HTTP mode (for systemd service)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host for SSE mode (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port for SSE mode (default: 8765)")
    args = parser.parse_args()

    if args.sse:
        asyncio.run(run_sse(args.host, args.port))
    else:
        asyncio.run(run_stdio())
