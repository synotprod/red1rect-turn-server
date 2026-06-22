package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	obfsMode := flag.Bool("obfs", false, "RTP-OBFS mode: disguise public UDP packets as RTP to avoid VK TURN relay throttling")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	publicAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}

	// addr is what dtls.ListenWithOptions binds to. In OBFS mode, DTLS binds
	// to an internal loopback port and runObfsRelay handles the public
	// socket, stripping/adding a fake RTP header around each datagram so it
	// passes whatever heuristic the VK TURN relay uses to throttle non-call
	// traffic. Backward compatible: default (-obfs not set) is unchanged.
	addr := publicAddr
	if *obfsMode {
		addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: publicAddr.Port + 1000}
		go func() {
			if relayErr := runObfsRelay(ctx, publicAddr, addr); relayErr != nil {
				log.Printf("obfs relay stopped: %v", relayErr)
			}
		}()
		log.Printf("RTP-OBFS enabled: public=%s -> internal=%s", publicAddr, addr)
	}
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Connect to a DTLS server
	listener, err := dtls.ListenWithOptions(
		"udp",
		addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		// Connection ID disabled as a diagnostic experiment: all DTLS
		// sessions (across both client identities) were observed dying
		// simultaneously with io.EOF after ~7-8 minutes of sustained
		// traffic — pion/dtls v3 (server) + v2 (client) CID handling is
		// the most likely culprit since it's the only non-default option
		// in this listener config.
	)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	fmt.Println("Listening")

	wg1 := sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			wg1.Wait()
			return
		default:
		}
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		wg1.Add(1)
		go func(conn net.Conn) {
			defer wg1.Done()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Printf("failed to close incoming connection: %s", closeErr)
				}
			}()
			log.Printf("Connection from %s\n", conn.RemoteAddr())

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			defer cancel1()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error: expected *dtls.Conn")
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Printf("Handshake failed: %v", err)
				return
			}
			log.Println("Handshake done")

			if *vlessMode {
				handleVLESSConnection(ctx, dtlsConn, *connect)
			} else {
				handleUDPConnection(ctx, conn, *connect)
			}

			log.Printf("Connection closed: %s\n", conn.RemoteAddr())
		}(conn)
	}
}

// handleUDPConnection forwards DTLS packets to a UDP backend (WireGuard).
func handleUDPConnection(ctx context.Context, conn net.Conn, connectAddr string) {
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err = serverConn.Close(); err != nil {
			log.Printf("failed to close outgoing connection: %s", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	ctx2, cancel2 := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		if err := conn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set incoming deadline: %s", err)
		}
		if err := serverConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set outgoing deadline: %s", err)
		}
	})
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err1 := conn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := conn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = serverConn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = serverConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err1 := serverConn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := serverConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = conn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = conn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
}

// handleVLESSConnection creates a KCP+smux session over DTLS and forwards
// each smux stream as a TCP connection to the backend (Xray/VLESS).
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	// 1. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer func() {
		if err := kcpSess.Close(); err != nil {
			log.Printf("failed to close KCP session: %v", err)
		}
	}()
	log.Printf("KCP session established (server)")

	// 2. Create smux server session over KCP
	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer func() {
		if err := smuxSess.Close(); err != nil {
			log.Printf("failed to close smux session: %v", err)
		}
	}()
	log.Printf("smux session established (server)")

	// 3. Accept smux streams and forward to backend via TCP
	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("smux accept error: %s", err)
			}
			break
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()

			defer func() {
				if err := s.Close(); err != nil && err != smux.ErrGoAway {
					log.Printf("failed to close smux stream: %v", err)
				}
			}()

			// Connect to backend (Xray/VLESS)
			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer func() {
				if err := backendConn.Close(); err != nil {
					log.Printf("failed to close backend connection: %v", err)
				}
			}()

			// Bidirectional copy
			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

// pipeConn copies data bidirectionally between two connections.
func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c1, c2); err != nil {
			log.Printf("pipeConn: c1<-c2 copy error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c2, c1); err != nil {
			log.Printf("pipeConn: c2<-c1 copy error: %v", err)
		}
	}()

	wg.Wait()

	// Reset deadlines
	_ = c1.SetDeadline(time.Time{})
	_ = c2.SetDeadline(time.Time{})
}

// --- RTP-OBFS relay ---
//
// VK TURN relays appear to throttle traffic that doesn't look like a real
// RTP/SRTP media stream — a single ChannelBind allocation otherwise tops out
// around tens of bytes/sec. We disguise every datagram as RTP v2 by
// prepending a 12-byte fixed RTP header (the payload itself, a DTLS record,
// is already opaque/encrypted, same as a real SRTP payload would be).
//
// runObfsRelay listens on the public address, strips the fake header from
// incoming packets and forwards the remainder to the DTLS listener bound on
// internalAddr (loopback), then re-wraps DTLS's replies on the way out.
// Must match golib's rtpObfsConn on the client byte-for-byte.
const obfsHeaderLen = 12

type obfsSession struct {
	local      *net.UDPConn
	remoteAddr *net.UDPAddr
	lastSeen   atomic.Int64
}

func runObfsRelay(ctx context.Context, publicAddr, internalAddr *net.UDPAddr) error {
	pubConn, err := net.ListenUDP("udp", publicAddr)
	if err != nil {
		return fmt.Errorf("obfs relay listen: %w", err)
	}
	context.AfterFunc(ctx, func() { _ = pubConn.Close() })

	var mu sync.Mutex
	sessions := make(map[string]*obfsSession)

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-10 * time.Minute).UnixNano()
				mu.Lock()
				for k, s := range sessions {
					if s.lastSeen.Load() < cutoff {
						_ = s.local.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, remoteAddr, readErr := pubConn.ReadFromUDP(buf)
		if readErr != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			log.Printf("obfs relay read: %v", readErr)
			continue
		}
		if n < obfsHeaderLen {
			continue // too short to be a wrapped packet — drop
		}
		payload := buf[obfsHeaderLen:n]

		key := remoteAddr.String()
		mu.Lock()
		sess, ok := sessions[key]
		if !ok {
			localConn, dialErr := net.DialUDP("udp", nil, internalAddr)
			if dialErr != nil {
				mu.Unlock()
				log.Printf("obfs relay dial internal: %v", dialErr)
				continue
			}
			sess = &obfsSession{local: localConn, remoteAddr: remoteAddr}
			sessions[key] = sess
			go relayInternalToPublic(ctx, pubConn, sess)
		}
		sess.lastSeen.Store(time.Now().UnixNano())
		mu.Unlock()

		if _, writeErr := sess.local.Write(payload); writeErr != nil {
			log.Printf("obfs relay forward to internal: %v", writeErr)
		}
	}
}

// relayInternalToPublic re-wraps DTLS replies from the internal loopback
// listener with a fake RTP header before sending them back to the real peer.
func relayInternalToPublic(ctx context.Context, pubConn *net.UDPConn, sess *obfsSession) {
	ssrc := rand.Uint32()
	var seq uint16
	var ts uint32
	buf := make([]byte, obfsHeaderLen+2048)
	for {
		n, err := sess.local.Read(buf[obfsHeaderLen:])
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		hdr := buf[:obfsHeaderLen]
		hdr[0] = 0x80 // V=2, P=0, X=0, CC=0
		hdr[1] = 111  // M=0, PT=111 (dynamic, Opus-like)
		binary.BigEndian.PutUint16(hdr[2:4], seq)
		binary.BigEndian.PutUint32(hdr[4:8], ts)
		binary.BigEndian.PutUint32(hdr[8:12], ssrc)
		seq++
		ts += 160

		if _, err := pubConn.WriteToUDP(buf[:obfsHeaderLen+n], sess.remoteAddr); err != nil {
			log.Printf("obfs relay write to public: %v", err)
			return
		}
	}
}
