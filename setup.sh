#!/usr/bin/env bash
# Kali Linux MCP Server — install and register as a systemd service.
# Run as root:  sudo bash setup.sh
# Or skip the service: bash setup.sh --user

set -euo pipefail

INSTALL_DIR="/opt/kali-mcp-server"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_NAME="kali-mcp-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PORT=8765
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── argument parsing ──────────────────────────────────────────────────────────
USER_MODE=false
for arg in "$@"; do
    [[ "$arg" == "--user" ]] && USER_MODE=true
done

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[ERR ]\033[0m  $*" >&2; exit 1; }

# ── user-mode: local venv, no systemd ────────────────────────────────────────
if $USER_MODE; then
    info "User-mode install: creating venv in $SCRIPT_DIR/venv ..."
    python3 -m venv "$SCRIPT_DIR/venv"
    "$SCRIPT_DIR/venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
    ok "Dependencies installed in venv."
    echo ""
    echo "Activate and run:"
    echo "  source $SCRIPT_DIR/venv/bin/activate"
    echo "  python3 $SCRIPT_DIR/kali_mcp_server.py --http --port $PORT"
    echo ""
    echo "Or for Claude Code CLI (stdio mode):"
    echo "  claude mcp add $SERVICE_NAME $SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/kali_mcp_server.py"
    exit 0
fi

# ── root check ────────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && die "Please run as root: sudo bash setup.sh"

RUN_AS="${SUDO_USER:-root}"
info "Service will run as user: $RUN_AS"

# ── step 1: copy files to /opt ────────────────────────────────────────────────
info "Copying server to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/kali_mcp_server.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt"   "$INSTALL_DIR/"
ok "Files copied."

# helper: re-copy latest server without full reinstall
if [[ "${1:-}" == "--update" ]]; then
    info "Update mode: copying latest server file and restarting service..."
    cp "$SCRIPT_DIR/kali_mcp_server.py" "$INSTALL_DIR/"
    systemctl restart "$SERVICE_NAME"
    ok "Service restarted with updated server."
    exit 0
fi

# ── step 2: create venv and install dependencies ──────────────────────────────
info "Creating Python venv at $VENV_DIR ..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
ok "Dependencies installed in venv."

# fix ownership
chown -R "$RUN_AS:$RUN_AS" "$INSTALL_DIR"

# ── step 3: write systemd unit ────────────────────────────────────────────────
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
ExecStart=${VENV_DIR}/bin/python3 ${INSTALL_DIR}/kali_mcp_server.py --http --host 0.0.0.0 --port ${PORT}
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

# ── step 4: enable and start ──────────────────────────────────────────────────
info "Enabling and starting $SERVICE_NAME ..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service is running!"
else
    warn "Service did not start cleanly. Check logs:"
    warn "  journalctl -u $SERVICE_NAME -n 50 --no-pager"
    exit 1
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Kali MCP Server is live on port $PORT"
echo ""
echo "  Commands:"
echo "    Status  : systemctl status $SERVICE_NAME"
echo "    Logs    : journalctl -u $SERVICE_NAME -f"
echo "    Stop    : systemctl stop $SERVICE_NAME"
echo "    Disable : systemctl disable $SERVICE_NAME"
echo ""
echo "  Claude Desktop / any SSE client:"
echo '    { "mcpServers": { "kali-mcp-server": { "url": "http://<KALI-IP>:'"$PORT"'/sse" } } }'
echo "════════════════════════════════════════════════════════"
