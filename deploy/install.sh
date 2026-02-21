#!/bin/bash
# install.sh — pgw-node installer script
# Usage: curl -fsSL https://github.com/Chinsusu/pgw-node/releases/latest/download/install.sh | bash
set -euo pipefail

REPO="Chinsusu/pgw-node"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/pgw-node"
KEY_PATH="$CONFIG_DIR/node.key"
SERVICE_FILE="/etc/systemd/system/pgw-node.service"
ARCH="${ARCH:-$(uname -m)}"

# Normalize arch
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

BIN_URL="https://github.com/$REPO/releases/latest/download/pgw-node-linux-$ARCH"

echo "==> Installing pgw-node from $BIN_URL"
curl -fsSL "$BIN_URL" -o "$INSTALL_DIR/pgw-node"
chmod +x "$INSTALL_DIR/pgw-node"

echo "==> Creating config directory: $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"

# Write env file if not exists
ENV_FILE="$CONFIG_DIR/pgw-node.env"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" << 'EOF'
# pgw-node configuration
# Required: Set these before starting the service
PGW_SERVER=http://YOUR_MASTER_SERVER:8080
PGW_NODE_ID=YOUR_NODE_ID
PGW_KEY_PATH=/etc/pgw-node/node.key
PGW_POLL_INTERVAL=15s
PGW_AGENT_URL=http://127.0.0.1:9090
EOF
  chmod 600 "$ENV_FILE"
  echo "==> Created env file: $ENV_FILE (EDIT THIS FILE before starting service)"
fi

# Install systemd service
cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=PGW Node Sync Daemon
After=network.target pgw-api.service

[Service]
Type=simple
EnvironmentFile=/etc/pgw-node/pgw-node.env
ExecStart=/usr/local/bin/pgw-node
Restart=always
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Generate keypair if not exists
if [ ! -f "$KEY_PATH" ]; then
  echo "==> Generating Ed25519 keypair..."
  pgw-node init
  echo ""
  echo "==> IMPORTANT: Register the public key above with your master server:"
  echo "    PUT /v1/nodes/{your-node-id} with {\"public_key\": \"<hex key>\"}"
else
  echo "==> Keypair already exists at $KEY_PATH"
  echo "==> Public key: $(pgw-node pubkey)"
fi

echo ""
echo "==> Installation complete!"
echo "    1. Edit $ENV_FILE with your master server URL and node ID"
echo "    2. Register the public key with master"
echo "    3. Run: systemctl enable --now pgw-node"
