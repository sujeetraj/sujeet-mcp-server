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

# ── disable DNS rebinding protection ──────────────────────────────────────────
# mcp >= 1.10 ships with TransportSecurityMiddleware that rejects every
# request whose Host header is not localhost. That kills remote clients
# (LM Studio, Claude Desktop on a different machine, etc.) with
# "ValueError: Request validation failed". We disable it here.
try:
    from mcp.server.transport_security import TransportSecuritySettings
    _security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
        allowed_hosts=["*"],
        allowed_origins=["*"],
    )
    if hasattr(mcp, "settings") and hasattr(mcp.settings, "transport_security"):
        mcp.settings.transport_security = _security
    # Some versions store it on the underlying server
    if hasattr(mcp, "_mcp_server"):
        for attr in ("_security", "security", "_transport_security", "transport_security"):
            if hasattr(mcp._mcp_server, attr):
                setattr(mcp._mcp_server, attr, _security)
except ImportError:
    pass  # older mcp version, no DNS rebinding protection to disable
except Exception as e:
    print(f"[warn] could not disable DNS rebinding protection: {e}", file=sys.stderr)


# ── helpers ───────────────────────────────────────────────────────────────────

# Maximum bytes of output to return to the LLM. Larger outputs blow the context
# window. ~10 KB is enough for almost any tool's interesting output.
_MAX_OUTPUT_BYTES = 10_000

# Map binary name → apt package name (when they differ)
_APT_PACKAGE_MAP = {
    "msfconsole":   "metasploit-framework",
    "theHarvester": "theharvester",
    "subfinder":    "subfinder",
    "ffuf":         "ffuf",
    "wafw00f":      "wafw00f",
    "wpscan":       "wpscan",
    "nuclei":       "nuclei",
    "searchsploit": "exploitdb",
    "smbmap":       "smbmap",
    "enum4linux":   "enum4linux",
    "exiftool":     "libimage-exiftool-perl",
}


def _truncate(text: str) -> str:
    """Cap output to _MAX_OUTPUT_BYTES so we don't flood the LLM context."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_OUTPUT_BYTES:
        return text
    head = encoded[: _MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    omitted = len(encoded) - _MAX_OUTPUT_BYTES
    return f"{head}\n\n[... output truncated, {omitted} more bytes omitted ...]"


def _require(binary: str) -> Optional[str]:
    """Return None if `binary` is on PATH, otherwise return an install hint."""
    if shutil.which(binary):
        return None
    pkg = _APT_PACKAGE_MAP.get(binary, binary)
    return (
        f"[not installed] '{binary}' is not on this system.\n"
        f"Install it with:  sudo apt install -y {pkg}"
    )


def _run(cmd: list[str], timeout: int = 120, stdin: Optional[str] = None) -> str:
    """Run a shell command and return combined output string (truncated)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=stdin,
        )
        parts = []
        if r.stdout.strip():
            parts.append(r.stdout.strip())
        if r.stderr.strip():
            parts.append(f"[stderr]\n{r.stderr.strip()}")
        out = "\n".join(parts) if parts else f"(no output, exit code {r.returncode})"
        return _truncate(out)
    except subprocess.TimeoutExpired:
        return f"[timeout] Command exceeded {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        hint = _require(cmd[0])
        return hint or f"[not found] {cmd[0]}"
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
    """List common Kali Linux security tools, grouped by category, with install status."""
    categories = {
        "Network scanning":     ["nmap", "masscan", "arp-scan", "traceroute", "netcat", "socat"],
        "Recon / OSINT":        ["whois", "dig", "theHarvester", "subfinder", "whatweb",
                                 "wafw00f", "dnsenum", "fierce"],
        "Web app":              ["nikto", "gobuster", "ffuf", "dirb", "wfuzz", "wpscan",
                                 "nuclei", "sqlmap"],
        "Vuln assessment":      ["searchsploit"],
        "SMB / AD":             ["enum4linux", "smbmap", "smbclient", "crackmapexec"],
        "Password attacks":     ["hydra", "john", "hashcat", "hashid", "crunch"],
        "Forensics / files":    ["binwalk", "strings", "exiftool", "file", "foremost"],
        "Exploitation":         ["msfconsole"],
        "Wireless":             ["aircrack-ng", "airmon-ng"],
    }
    out = ["Kali Linux Tool Status:"]
    for cat, tools in categories.items():
        out.append(f"\n[{cat}]")
        for t in tools:
            mark = "✓" if shutil.which(t) else "✗"
            out.append(f"  {mark}  {t}")
    return "\n".join(out)


# ─── Reconnaissance / OSINT ────────────────────────────────────────────────────

@mcp.tool()
def theharvester_scan(domain: str, sources: str = "duckduckgo,bing,crtsh", limit: int = 100) -> str:
    """
    Harvest emails, subdomains, and hosts for a domain using public sources.
    Passive reconnaissance — does not touch the target directly.

    Args:
        domain:  Target domain (e.g. example.com)
        sources: Comma-separated source list (default: duckduckgo,bing,crtsh)
        limit:   Max results per source (default: 100)
    """
    if (hint := _require("theHarvester")):
        return hint
    cmd = ["theHarvester", "-d", domain, "-l", str(limit), "-b", sources]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=180)}"


@mcp.tool()
def subfinder_scan(domain: str, all_sources: bool = False) -> str:
    """
    Passive subdomain enumeration via subfinder.

    Args:
        domain:      Target domain (e.g. example.com)
        all_sources: Use all configured sources (slower but more thorough)
    """
    if (hint := _require("subfinder")):
        return hint
    cmd = ["subfinder", "-d", domain, "-silent"]
    if all_sources:
        cmd.append("-all")
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=120)}"


@mcp.tool()
def whatweb_scan(target: str, aggression: int = 1) -> str:
    """
    Identify web technologies running on a target (CMS, framework, server, etc.).

    Args:
        target:     URL or hostname (e.g. https://example.com)
        aggression: 1=stealthy, 3=aggressive, 4=heavy (default: 1)
    """
    if (hint := _require("whatweb")):
        return hint
    cmd = ["whatweb", "-a", str(aggression), target]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=60)}"


@mcp.tool()
def wafw00f_scan(target: str) -> str:
    """
    Detect and identify Web Application Firewalls in front of a target.

    Args:
        target: URL (e.g. https://example.com)
    """
    if (hint := _require("wafw00f")):
        return hint
    cmd = ["wafw00f", target]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=60)}"


# ─── Network scanning ──────────────────────────────────────────────────────────

@mcp.tool()
def masscan_scan(target: str, ports: str = "1-1000", rate: int = 1000) -> str:
    """
    Ultra-fast TCP port scanner. Requires root privileges (raw sockets).
    Only use against authorized targets.

    Args:
        target: IP, range, or CIDR (e.g. 10.0.0.0/24)
        ports:  Port spec (e.g. '80,443,8000-9000'), default '1-1000'
        rate:   Packets per second (default: 1000)
    """
    if (hint := _require("masscan")):
        return hint
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate)]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def arp_scan(interface: Optional[str] = None, target: str = "--localnet") -> str:
    """
    Discover hosts on the local network via ARP requests. Requires root.

    Args:
        interface: Network interface (e.g. eth0). Auto-selected if omitted.
        target:    '--localnet' for the local subnet, or a CIDR/IP range.
    """
    if (hint := _require("arp-scan")):
        return hint
    cmd = ["arp-scan"]
    if interface:
        cmd += ["-I", interface]
    cmd.append(target)
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=60)}"


@mcp.tool()
def traceroute_scan(target: str, max_hops: int = 30) -> str:
    """
    Trace the network path to a target host.

    Args:
        target:   Hostname or IP
        max_hops: Maximum hops (default: 30)
    """
    if (hint := _require("traceroute")):
        return hint
    cmd = ["traceroute", "-m", str(max_hops), target]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=60)}"


# ─── Web application ───────────────────────────────────────────────────────────

@mcp.tool()
def ffuf_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: Optional[str] = None,
    match_codes: str = "200,204,301,302,307,401,403",
) -> str:
    """
    Fast web fuzzer. URL must contain 'FUZZ' as the placeholder, e.g.
    'https://example.com/FUZZ'.

    Args:
        url:         Target URL with FUZZ keyword (e.g. https://site.com/FUZZ)
        wordlist:    Path to wordlist (default: dirb/common.txt)
        extensions:  Comma-separated extensions, e.g. 'php,html'
        match_codes: HTTP status codes to report (default: 200,204,301,302,307,401,403)
    """
    if (hint := _require("ffuf")):
        return hint
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-mc", match_codes, "-s"]
    if extensions:
        cmd += ["-e", "," + extensions if not extensions.startswith(",") else extensions]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def wpscan_scan(url: str, enumerate: str = "vp,vt,u") -> str:
    """
    WordPress vulnerability scanner. Requires WPSCAN_API_TOKEN env var for
    full vulnerability data.

    Args:
        url:       WordPress site URL (e.g. https://blog.example.com)
        enumerate: What to enum — 'vp' vuln plugins, 'vt' vuln themes,
                   'u' users, 'ap' all plugins. Default: 'vp,vt,u'
    """
    if (hint := _require("wpscan")):
        return hint
    cmd = ["wpscan", "--url", url, "--enumerate", enumerate, "--no-update", "--random-user-agent"]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def nuclei_scan(target: str, severity: str = "medium,high,critical", tags: Optional[str] = None) -> str:
    """
    Run nuclei template-based vulnerability scanner against a target.

    Args:
        target:   URL or hostname (e.g. https://example.com)
        severity: Comma-separated levels — info,low,medium,high,critical
                  (default: 'medium,high,critical')
        tags:     Optional template tag filter (e.g. 'cve,exposure,misconfig')
    """
    if (hint := _require("nuclei")):
        return hint
    cmd = ["nuclei", "-u", target, "-severity", severity, "-silent", "-nc"]
    if tags:
        cmd += ["-tags", tags]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


# ─── Vulnerability assessment ──────────────────────────────────────────────────

@mcp.tool()
def nmap_vuln_scan(target: str, ports: Optional[str] = None) -> str:
    """
    Run nmap with the 'vuln' NSE script category — checks for known CVEs and
    common vulnerabilities on open ports.

    Args:
        target: IP or hostname
        ports:  Optional port spec (e.g. '80,443,8080'); defaults to top 1000
    """
    if (hint := _require("nmap")):
        return hint
    cmd = ["nmap", "-sV", "--script", "vuln"]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=600)}"


@mcp.tool()
def searchsploit_lookup(query: str) -> str:
    """
    Search the local Exploit-DB database for known exploits matching a query.

    Args:
        query: Search terms — software name, CVE, or keywords
               (e.g. 'apache 2.4.49' or 'CVE-2021-41773')
    """
    if (hint := _require("searchsploit")):
        return hint
    cmd = ["searchsploit", "--color", "false"] + query.split()
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=30)}"


# ─── SMB / Active Directory ────────────────────────────────────────────────────

@mcp.tool()
def enum4linux_scan(target: str, options: str = "-a") -> str:
    """
    Enumerate information from a Windows/Samba host (shares, users, groups,
    policies, OS version).

    Args:
        target:  IP or hostname of the SMB server
        options: enum4linux flags (default: '-a' for all checks)
    """
    if (hint := _require("enum4linux")):
        return hint
    cmd = ["enum4linux"] + options.split() + [target]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=300)}"


@mcp.tool()
def smbmap_scan(target: str, username: str = "", password: str = "") -> str:
    """
    List SMB shares and access permissions on a target.

    Args:
        target:   IP or hostname
        username: SMB username (empty = anonymous/guest)
        password: SMB password (empty = anonymous/guest)
    """
    if (hint := _require("smbmap")):
        return hint
    cmd = ["smbmap", "-H", target, "-u", username or "guest", "-p", password]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=120)}"


# ─── Forensics / file analysis ─────────────────────────────────────────────────

@mcp.tool()
def binwalk_scan(file_path: str, extract: bool = False) -> str:
    """
    Analyze a binary or firmware file — find embedded files, signatures,
    and known structures.

    Args:
        file_path: Absolute path to the file on the Kali machine
        extract:   If True, also extract embedded data (-e flag)
    """
    if (hint := _require("binwalk")):
        return hint
    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(file_path)
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=120)}"


@mcp.tool()
def strings_extract(file_path: str, min_length: int = 6) -> str:
    """
    Extract printable strings from a binary file.

    Args:
        file_path:  Absolute path to the file
        min_length: Minimum string length (default: 6)
    """
    if (hint := _require("strings")):
        return hint
    cmd = ["strings", "-n", str(min_length), file_path]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=60)}"


@mcp.tool()
def exiftool_read(file_path: str) -> str:
    """
    Read EXIF and other metadata from a file (image, PDF, document, etc.).

    Args:
        file_path: Absolute path to the file
    """
    if (hint := _require("exiftool")):
        return hint
    cmd = ["exiftool", file_path]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=30)}"


@mcp.tool()
def file_info(file_path: str) -> str:
    """
    Identify the type of a file via magic-byte inspection.

    Args:
        file_path: Absolute path to the file
    """
    if (hint := _require("file")):
        return hint
    cmd = ["file", "-b", file_path]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=10)}"


# ─── TLS / certificate inspection ──────────────────────────────────────────────

@mcp.tool()
def openssl_cert_info(host: str, port: int = 443) -> str:
    """
    Connect to a TLS service and dump the server certificate (subject, issuer,
    validity period, SANs, signature algorithm).

    Args:
        host: Hostname or IP
        port: TLS port (default: 443)
    """
    if (hint := _require("openssl")):
        return hint
    # openssl s_client requires stdin closed to exit cleanly
    fetch = ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", host, "-showcerts"]
    raw = _run(fetch, timeout=15, stdin="")
    # Pipe certificate text into x509 for human-readable parsing
    parse = ["openssl", "x509", "-noout", "-text"]
    parsed = _run(parse, timeout=10, stdin=raw)
    return f"$ openssl s_client → openssl x509\n\n{parsed}"


# ─── Self-management ───────────────────────────────────────────────────────────

@mcp.tool()
def apt_install_tool(package: str) -> str:
    """
    Install a missing Kali tool via apt. Requires the MCP server to run as root
    (or with passwordless sudo). Only standard Kali repository packages are allowed.

    Args:
        package: apt package name (e.g. 'nuclei', 'subfinder', 'wpscan')
    """
    # Whitelist of packages we're willing to auto-install — must match values
    # in _APT_PACKAGE_MAP plus a few common extras.
    allowed = set(_APT_PACKAGE_MAP.values()) | {
        "nmap", "nikto", "gobuster", "sqlmap", "whatweb", "wafw00f",
        "dnsenum", "fierce", "masscan", "arp-scan", "traceroute",
        "ffuf", "dirb", "wfuzz", "wpscan", "nuclei", "exploitdb",
        "enum4linux", "smbmap", "binwalk", "exiftool", "hashid",
        "hydra", "john", "hashcat", "openssl",
    }
    if package not in allowed:
        return f"[blocked] '{package}' is not in the allowed install list."

    # Use DEBIAN_FRONTEND=noninteractive to skip prompts
    cmd = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", package]
    return f"$ {' '.join(cmd)}\n\n{_run(cmd, timeout=600)}"


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


# ── HTTP server helpers (defined BEFORE __main__ so they are in scope) ────────

def _start_http_manual(host: str, port: int) -> None:
    """
    Manual SSE transport using raw ASGI (scope, receive, send).
    Bypasses Starlette's Request wrapper — avoids the request._send
    issue that breaks session lookup and causes HTTP 421 errors.
    """
    from mcp.server import Server as _Server
    from mcp.server.models import InitializationOptions
    from mcp.server.sse import SseServerTransport
    import uvicorn

    _srv = _Server("kali-mcp-server")
    _transport = SseServerTransport("/messages/")

    @_srv.list_tools()
    async def _list_tools():
        return await mcp._mcp_server.list_tools()

    @_srv.call_tool()
    async def _call_tool(name, arguments):
        return await mcp._mcp_server.call_tool(name, arguments)

    init_opts = InitializationOptions(
        server_name="kali-mcp-server",
        server_version="1.0.0",
        capabilities=_srv.get_capabilities(
            notification_options=None, experimental_capabilities={}
        ),
    )

    # Raw ASGI handler — scope/receive/send passed directly, no Starlette wrapper
    async def handle_sse(scope, receive, send):
        async with _transport.connect_sse(scope, receive, send) as (read, write):
            await _srv.run(read, write, init_opts)

    async def _send_status(send, status: int, body: bytes = b"") -> None:
        await send({
            "type": "http.response.start", "status": status,
            "headers": [[b"content-type", b"text/plain"]],
        })
        await send({"type": "http.response.body", "body": body})

    # Minimal ASGI router with strict method checks.
    # Note: LM Studio first tries POST /sse (Streamable HTTP). We must return
    # 405 instead of routing to connect_sse, otherwise mcp's request validation
    # raises ValueError and crashes the worker.
    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        path   = scope.get("path", "")
        method = scope.get("method", "GET")

        if path == "/sse":
            if method == "GET":
                try:
                    await handle_sse(scope, receive, send)
                except Exception as e:
                    print(f"[sse error] {e}", file=sys.stderr)
            else:
                await _send_status(send, 405, b"Use GET for SSE")
        elif path.startswith("/messages"):
            if method == "POST":
                await _transport.handle_post_message(scope, receive, send)
            else:
                await _send_status(send, 405, b"Use POST for messages")
        else:
            await _send_status(send, 404, b"Not found")

    print(f"Kali MCP Server → http://{host}:{port}/sse", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level="info")


def _start_http(host: str, port: int) -> None:
    """Start the HTTP server, trying FastMCP API variants across mcp versions."""
    try:
        import uvicorn
    except ImportError:
        print("HTTP mode requires uvicorn:  pip install uvicorn starlette", file=sys.stderr)
        sys.exit(1)

    # 1. mcp ≥ 1.6 — get_app() returns Starlette app with /mcp + /sse
    if hasattr(mcp, "get_app"):
        print(f"Kali MCP Server → http://{host}:{port}/sse + /mcp", file=sys.stderr)
        uvicorn.run(mcp.get_app(), host=host, port=port, log_level="info")
        return

    # 2. mcp 1.2–1.5 — sse_app() returns Starlette app with /sse + /messages/
    if hasattr(mcp, "sse_app"):
        print(f"Kali MCP Server → http://{host}:{port}/sse  (sse_app)", file=sys.stderr)
        uvicorn.run(mcp.sse_app(), host=host, port=port, log_level="info")
        return

    # 3. All other versions — raw ASGI manual transport (no request._send bug)
    _start_http_manual(host, port)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kali Linux MCP Server")
    parser.add_argument(
        "--http", action="store_true",
        help="Run in HTTP mode (LM Studio, Claude Desktop, any remote MCP client).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    args = parser.parse_args()

    if args.http:
        _start_http(args.host, args.port)
    else:
        mcp.run(transport="stdio")
