#!/bin/bash
# Red1rect Turn Server — deploy script
# Installs and starts the server on a fresh Ubuntu/Debian VPS.
# Usage: bash deploy.sh
set -e

GO_VERSION="1.24.3"
INSTALL_DIR="/opt/red1rect-server"
WG_PORT=51820
DTLS_PORT=57000
OBFS_PORT=57010

echo "[1/6] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools curl git

echo "[2/6] Installing Go $GO_VERSION..."
if ! go version 2>/dev/null | grep -q "$GO_VERSION"; then
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
    export PATH="/usr/local/go/bin:$PATH"
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile
fi
go version

echo "[3/6] Building server..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/src"
cd "$INSTALL_DIR/src"
go build -o "$INSTALL_DIR/server" ./server/
echo "✓ Build OK: $INSTALL_DIR/server"

echo "[4/6] Setting up WireGuard..."
if [ ! -f /etc/wireguard/wg0.conf ]; then
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    SERVER_PRIVATE=$(cat /etc/wireguard/server_private.key)
    SERVER_PUBLIC=$(cat /etc/wireguard/server_public.key)
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE
Address = 10.66.68.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o \$(ip route | grep default | awk '{print \$5}') -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o \$(ip route | grep default | awk '{print \$5}') -j MASQUERADE
EOF
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    echo "✓ WireGuard config created. Server public key:"
    echo "  $SERVER_PUBLIC"
fi
systemctl enable --now wg-quick@wg0 || true

echo "[5/6] Creating systemd services..."
cat > /etc/systemd/system/red1rect-server.service <<EOF
[Unit]
Description=Red1rect TURN Server (port $DTLS_PORT)
After=network.target

[Service]
ExecStart=$INSTALL_DIR/server -listen 0.0.0.0:$DTLS_PORT -connect 127.0.0.1:$WG_PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/red1rect-server-obfs.service <<EOF
[Unit]
Description=Red1rect TURN Server RTP-OBFS (port $OBFS_PORT)
After=network.target

[Service]
ExecStart=$INSTALL_DIR/server -listen 0.0.0.0:$OBFS_PORT -connect 127.0.0.1:$WG_PORT -obfs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now red1rect-server red1rect-server-obfs

echo "[6/6] Opening firewall ports..."
ufw allow $DTLS_PORT/udp 2>/dev/null || iptables -A INPUT -p udp --dport $DTLS_PORT -j ACCEPT
ufw allow $OBFS_PORT/udp 2>/dev/null || iptables -A INPUT -p udp --dport $OBFS_PORT -j ACCEPT
ufw allow $WG_PORT/udp 2>/dev/null || iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT

echo ""
echo "✓ Done! Services running:"
systemctl status red1rect-server red1rect-server-obfs --no-pager | grep -E "Active|Main PID"
echo ""
echo "Server IP: $(curl -s ifconfig.me)"
echo "DTLS port (no-obfs): $DTLS_PORT"
echo "DTLS port (obfs):    $OBFS_PORT"
echo "WireGuard port:      $WG_PORT"
echo ""
echo "WireGuard server public key:"
cat /etc/wireguard/server_public.key
