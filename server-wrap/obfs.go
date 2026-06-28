package main

// RTP-OBFS relay — strips/adds fake 12-byte RTP v2 header around DTLS packets.
// Identical logic to server/main.go runObfsRelay / relayInternalToPublic.

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

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

	// Cleanup stale sessions every minute.
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
			log.Printf("[obfs] read: %v", readErr)
			continue
		}
		if n < obfsHeaderLen {
			continue
		}
		payload := buf[obfsHeaderLen:n]

		key := remoteAddr.String()
		mu.Lock()
		sess, ok := sessions[key]
		if !ok {
			localConn, dialErr := net.DialUDP("udp", nil, internalAddr)
			if dialErr != nil {
				mu.Unlock()
				log.Printf("[obfs] dial internal: %v", dialErr)
				continue
			}
			sess = &obfsSession{local: localConn, remoteAddr: remoteAddr}
			sessions[key] = sess
			go relayInternalToPublic(ctx, pubConn, sess)
		}
		sess.lastSeen.Store(time.Now().UnixNano())
		mu.Unlock()

		if _, writeErr := sess.local.Write(payload); writeErr != nil {
			log.Printf("[obfs] forward to internal: %v", writeErr)
		}
	}
}

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
			default:
			}
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		hdr := buf[:obfsHeaderLen]
		hdr[0] = 0x80
		hdr[1] = 111
		binary.BigEndian.PutUint16(hdr[2:4], seq)
		binary.BigEndian.PutUint32(hdr[4:8], ts)
		binary.BigEndian.PutUint32(hdr[8:12], ssrc)
		seq++
		ts += 160

		if _, err := pubConn.WriteToUDP(buf[:obfsHeaderLen+n], sess.remoteAddr); err != nil {
			log.Printf("[obfs] write to public: %v", err)
			return
		}
	}
}
