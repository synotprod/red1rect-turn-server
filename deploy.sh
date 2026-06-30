#!/usr/bin/env bash
# Red1rect WRAP VPN server — деплой (1 поток) на свежую Ubuntu/Debian VPS.
# Запуск от root:  bash deploy.sh [PUBLIC_IP]
# PUBLIC_IP опционален — по умолчанию автоопределяется.
set -e

PUBLIC_IP="${1:-$(curl -s -4 --max-time 8 ifconfig.me || hostname -I | awk '{print $1}')}"
EXT_IF="$(ip route | awk '/^default/{print $5; exit}')"
LISTEN_PORT=57011      # внешний порт сервера (DTLS-over-TURN)
WG_IF=wg1
WG_PORT=51820

echo "==> Public IP: $PUBLIC_IP | внешний интерфейс: $EXT_IF"
[ -z "$EXT_IF" ] && { echo "Не нашёл внешний интерфейс"; exit 1; }

echo "==> Зависимости"
apt-get update -y
apt-get install -y wireguard iptables golang-go curl git ca-certificates

echo "==> ip_forward"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "==> WireGuard $WG_IF (сервер. WRAP-клиенты получают 10.66.66.X динамически)"
mkdir -p /etc/wireguard
if [ ! -f /etc/wireguard/${WG_IF}_private.key ]; then
    umask 077
    wg genkey | tee /etc/wireguard/${WG_IF}_private.key | wg pubkey > /etc/wireguard/${WG_IF}_public.key
fi
PRIV="$(cat /etc/wireguard/${WG_IF}_private.key)"

cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
PrivateKey = $PRIV
Address = 10.66.68.1/24
ListenPort = $WG_PORT
MTU = 1280
PostUp = ip route add 10.66.66.0/24 dev $WG_IF; iptables -t nat -A POSTROUTING -s 10.66.68.0/24 -o $EXT_IF -j MASQUERADE; iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o $EXT_IF -j MASQUERADE; iptables -I FORWARD -i $WG_IF -j ACCEPT; iptables -I FORWARD -o $WG_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ip route del 10.66.66.0/24 dev $WG_IF 2>/dev/null; iptables -t nat -D POSTROUTING -s 10.66.68.0/24 -o $EXT_IF -j MASQUERADE; iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o $EXT_IF -j MASQUERADE; iptables -D FORWARD -i $WG_IF -j ACCEPT; iptables -D FORWARD -o $WG_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
EOF

systemctl enable wg-quick@${WG_IF} >/dev/null 2>&1
systemctl restart wg-quick@${WG_IF}

echo "==> Сборка server-wrap"
cd "$(dirname "$(readlink -f "$0")")/server-wrap"
go build -o /opt/server-wrap .

echo "==> systemd server-wrap.service"
cat > /etc/systemd/system/server-wrap.service <<EOF
[Unit]
Description=Red1rect VPN Server (WRAP protocol)
After=network.target

[Service]
Type=simple
ExecStart=/opt/server-wrap -listen 0.0.0.0:$LISTEN_PORT -wg $WG_IF -wg-public-ip $PUBLIC_IP -wg-port $WG_PORT -store /etc/red1rect-passwords.json -api 127.0.0.1:8765 -dns 1.1.1.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable server-wrap >/dev/null 2>&1
systemctl restart server-wrap
sleep 1
systemctl --no-pager status server-wrap | head -6 || true

echo ""
echo "================ ГОТОВО ================"
echo "Добавить клиента (пароль):"
echo "  curl -s -X POST -H 'Content-Type: application/json' -d '{\"password\":\"МОЙ_ПАРОЛЬ\"}' http://127.0.0.1:8765/api/password"
echo "  → вернёт client_ip (напр. 10.66.66.2)"
echo "Ключ для клиента:"
echo "  red1rect://$PUBLIC_IP:$LISTEN_PORT:МОЙ_ПАРОЛЬ:VK_HASH:CLIENT_IP"
