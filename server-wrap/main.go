// server-wrap: Red1rect VPN server with password auth and dynamic WireGuard peer issuance.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// WGConfig is sent to client after successful auth.
type WGConfig struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ClientIP   string `json:"client_ip"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	DNS        string `json:"dns"`
}

var (
	magicAuth = [4]byte{'R', '1', 'B', 'S'}
	magicOK   = [4]byte{'R', '1', 'O', 'K'}
	magicErr  = [4]byte{'R', '1', 'E', 'R'}
	magicPing = [4]byte{'P', 'I', 'N', 'G'}
	magicPong = [4]byte{'P', 'O', 'N', 'G'}
)

func main() {
	listen := flag.String("listen", "0.0.0.0:57011", "public listen address (UDP, RTP-OBFS)")
	wgIface := flag.String("wg", "wg1", "WireGuard interface name")
	wgSubnet := flag.String("subnet", "10.66.66.0/24", "WireGuard client IP subnet")
	wgServerIP := flag.String("wg-server-ip", "10.66.66.1", "WireGuard server IP in subnet")
	wgServerPub := flag.String("wg-public-ip", "", "server public IP for WG endpoint (required)")
	wgPort := flag.Int("wg-port", 51820, "WireGuard listen port")
	storePath := flag.String("store", "/etc/red1rect-passwords.json", "password store path")
	apiAddr := flag.String("api", "127.0.0.1:8765", "HTTP API listen address")
	dns := flag.String("dns", "1.1.1.1", "DNS server to give clients")
	flag.Parse()

	if *wgServerPub == "" {
		log.Fatal("-wg-public-ip is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; cancel() }()

	mgr, err := NewWGManager(*wgIface, *wgServerIP, *wgSubnet)
	if err != nil {
		log.Fatalf("wg manager: %v", err)
	}

	store, err := NewPasswordStore(*storePath)
	if err != nil {
		log.Fatalf("password store: %v", err)
	}

	mgr.SyncPeers(store)

	serverPubKey, err := mgr.ServerPublicKey()
	if err != nil {
		log.Fatalf("server wg pubkey: %v", err)
	}
	log.Printf("[main] server WG public key: %s...", serverPubKey[:8])

	store.StartAPI(*apiAddr, mgr)

	publicAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("resolve %s: %v", *listen, err)
	}
	internalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: publicAddr.Port + 1000}

	go func() {
		if err := runObfsRelay(ctx, publicAddr, internalAddr); err != nil {
			log.Printf("[obfs] relay error: %v", err)
		}
	}()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		log.Fatalf("cert: %v", err)
	}

	listener, err := dtls.ListenWithOptions("udp", internalAddr,
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
	)
	if err != nil {
		log.Fatalf("dtls listen: %v", err)
	}
	context.AfterFunc(ctx, func() { listener.Close() })

	log.Printf("[main] listening on %s (internal: %s)", publicAddr, internalAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[main] accept: %v", err)
				continue
			}
		}
		go handleConn(ctx, conn, store, mgr, serverPubKey, *wgServerPub, *wgPort, *dns)
	}
}

func handleConn(ctx context.Context, conn net.Conn, store *PasswordStore, mgr *WGManager, serverPubKey, serverPublicIP string, wgPort int, dns string) {
	remote := conn.RemoteAddr()
	log.Printf("[conn] new from %v", remote)
	defer func() {
		conn.Close()
		log.Printf("[conn] closed %v", remote)
	}()

	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// DTLS is datagram-based: read full auth packet in one call.
	authBuf := make([]byte, 512)
	n, err := conn.Read(authBuf)
	if err != nil {
		log.Printf("[conn] read header: %v", err)
		return
	}
	if n < 6 {
		log.Printf("[conn] packet too short: %d", n)
		return
	}
	if [4]byte(authBuf[:4]) != magicAuth {
		log.Printf("[conn] bad magic: %x", authBuf[:4])
		return
	}
	plen := binary.BigEndian.Uint16(authBuf[4:6])
	if plen == 0 || plen > 256 {
		log.Printf("[conn] bad password length: %d", plen)
		return
	}
	if n < 6+int(plen) {
		log.Printf("[conn] packet too short for password: %d < %d", n, 6+int(plen))
		return
	}
	password := string(authBuf[6 : 6+int(plen)])

	if !store.Has(password) {
		log.Printf("[conn] unknown password from %v", remote)
		sendError(conn, "unauthorized")
		return
	}

	entry, err := store.GetOrCreate(password, mgr)
	if err != nil {
		log.Printf("[conn] getorcreate: %v", err)
		sendError(conn, "server error")
		return
	}

	if err := mgr.AddPeer(entry.WGPublicKey, entry.ClientIP); err != nil {
		log.Printf("[conn] add peer (may already exist): %v", err)
	}

	cfg := WGConfig{
		PrivateKey: entry.WGPrivateKey,
		PublicKey:  serverPubKey,
		ClientIP:   entry.ClientIP,
		ServerIP:   serverPublicIP,
		ServerPort: wgPort,
		DNS:        dns,
	}
	cfgJSON, _ := json.Marshal(cfg)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := sendPacket(conn, magicOK, cfgJSON); err != nil {
		log.Printf("[conn] send config: %v", err)
		return
	}
	conn.SetDeadline(time.Time{})

	log.Printf("[conn] auth OK %v (ip=%s)", remote, entry.ClientIP)

	// Мультипоток: коннекты одного пароля агрегируются в ОДИН WG-прокси
	// (общий localUDP↔wg1). Ответы WG раздаются по живым коннектам.
	sess, err := getOrCreateSession(password, wgPort)
	if err != nil {
		log.Printf("[conn] session: %v", err)
		return
	}
	sess.addConn(conn)
	defer sess.removeConn(conn)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	// DTLS → wg1: WG-пакеты от клиента в ОБЩИЙ localUDP сессии.
	go func() {
		defer connCancel()
		buf := make([]byte, 65536)
		for {
			conn.SetDeadline(time.Now().Add(70 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n == 4 && [4]byte(buf[:4]) == magicPong {
				continue
			}
			if _, err := sess.localUDP.WriteToUDP(buf[:n], sess.wg1Addr); err != nil {
				return
			}
		}
	}()
	// wg1 → DTLS направление обслуживает общая горутина сессии (wgToConns).

	// PING keepalive: server → client каждые 20с (детект мёртвых коннектов).
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-connCtx.Done():
			return
		case <-ticker.C:
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(magicPing[:]); err != nil {
				log.Printf("[conn] ping: %v", err)
				return
			}
			conn.SetDeadline(time.Time{})
		}
	}
}

func sendPacket(conn net.Conn, magic [4]byte, payload []byte) error {
	pkt := make([]byte, 6+len(payload))
	copy(pkt[:4], magic[:])
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	copy(pkt[6:], payload)
	_, err := conn.Write(pkt)
	return err
}

func sendError(conn net.Conn, msg string) {
	sendPacket(conn, magicErr, []byte(msg))
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
