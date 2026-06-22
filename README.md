# Red1rect Turn Server

DTLS server for Red1rect VPN — routes WireGuard traffic through VK TURN relays.

Fork of [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) with RTP-obfuscation added.

## Changes vs upstream

- `-obfs` flag: RTP-OBFS mode — wraps/strips a fake 12-byte RTP v2 header around each UDP datagram so VK TURN doesn't throttle non-call traffic (~10+ MB/s vs 0.03 KB/s without)
- DTLS Connection ID disabled (simultaneous session drops with pion/dtls v2 client)
- Systemd-compatible signal handling

## Ports

| Port  | Mode            |
|-------|-----------------|
| 57000 | Standard DTLS   |
| 57010 | DTLS + RTP-OBFS |
| 51820 | WireGuard       |

## Deploy on a new VPS (Ubuntu/Debian)

```bash
git clone https://github.com/synotprod/red1rect-turn-server
cd red1rect-turn-server
bash deploy.sh
```

The script:
1. Installs Go and WireGuard
2. Builds the server binary
3. Creates systemd services for both ports
4. Opens firewall ports

## Manual build

```bash
go build -o server ./server/
./server -listen 0.0.0.0:57000 -connect 127.0.0.1:51820
./server -listen 0.0.0.0:57010 -connect 127.0.0.1:51820 -obfs
```
