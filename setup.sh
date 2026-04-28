#!/usr/bin/env bash
# Kali Linux MCP Server — install and register as a systemd service.
# Run as root:  sudo bash setup.sh
# Or as a normal user for local-only install (no service): bash setup.sh --user

set -euo pipefail

INSTALL_DIR="/opt/kali-mcp-server"
SERVICE_NAME="kali-mcp-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PORT=8765
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── argument parsing ──────────────────────────────────────────────────────────
USER_MODE=false
for arg in "$@"; do
    [[ "$arg" == "--user" ]] && USER_MODE=true
done

# ── helper ────────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[ERR ]\033[0m  $*" >&2; exit 1; }

# ── user-mode (no root, no systemd service) ───────────────────────────────────
if $USER_MODE; then
    info "User-mode install: dependencies only (no systemd service)."
    pip3 install --user -r "$SCRIPT_DIR/requirements.txt"
    ok "Dependencies installed."
    echo ""
    echo "To run manually in SSE mode:"
    echo "  python3 $SCRIPT_DIR/kali_mcp_server.py --sse --port $PORT"
    echo ""
    echo "To run in stdio mode (for Claude Code CLI):"
    echo "  claude mcp add $SERVICE_NAME python3 $SCRIPT_DIR/kali_mcp_server.py"
    exit 0
fi

# ── root check ────────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && die "Please run as root: sudo bash setup.sh"

# ── detect the non-root user that will own the service ───────────────────────
# Use SUDO_USER if available, otherwise fall back to 'kali'
RUN_AS="${SUDO_USER:-kali}"
info "Service will run as user: $RUN_AS"

# ── step 1: install python dependencies system-wide ──────────────────────────
info "Installing Python dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt"
ok "Dependencies installed."

# ── step 2: copy server to /opt ───────────────────────────────────────────────
info "Copying server to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/kali_mcp_server.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt"   "$INSTALL_DIR/"
chown -R "$RUN_AS:$RUN_AS" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 640 "$INSTALL_DIR/kali_mcp_server.py"
ok "Files copied."

# ── step 3: write systemd unit file ──────────────────────────────────────────
info "Writing systemd service to $SERVICE_FILE ..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Kali Linux MCP Server (SSE/HTTP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_AS}
Group=${RUN_AS}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/kali_mcp_server.py --sse --host 0.0.0.0 --port ${PORT}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
ok "Service file written."

# ── step 4: enable and start the service ─────────────────────────────────────
info "Enabling and starting $SERVICE_NAME ..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# wait a moment and check status
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service is running!"
else
    warn "Service did not start cleanly. Check logs with:"
    warn "  journalctl -u $SERVICE_NAME -n 50 --no-pager"
    exit 1
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Kali MCP Server is live on port $PORT"
echo ""
echo "  Useful commands:"
echo "    Status  : systemctl status $SERVICE_NAME"
echo "    Logs    : journalctl -u $SERVICE_NAME -f"
echo "    Stop    : systemctl stop $SERVICE_NAME"
echo "    Disable : systemctl disable $SERVICE_NAME"
echo ""
echo "  Claude Desktop config (remote connection):"
echo '  Add to ~/.config/Claude/claude_desktop_config.json:'
echo '  {'
echo '    "mcpServers": {'
echo "      \"$SERVICE_NAME\": {"
echo '        "url": "http://<KALI-IP>:'"$PORT"'/sse"'
echo '      }'
echo '    }'
echo '  }'
echo "════════════════════════════════════════════════════════"
