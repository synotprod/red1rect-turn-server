package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// peerSession агрегирует НЕСКОЛЬКО DTLS-коннектов одного пароля в ОДИН WG-прокси.
// Все коннекты делят общий localUDP↔wg1 (wg1 видит один эндпоинт, не «прыгает»).
// Ответы WG раздаются по живым коннектам round-robin'ом. Это даёт мультипоток:
// клиент гонит WG по N потокам, любой живой несёт трафик, мёртвый не мешает.
// chunkSize — пакетов подряд в один коннект перед переключением (как у клиента).
const chunkSize = 8

type peerSession struct {
	password   string
	localUDP   *net.UDPConn
	wg1Addr    *net.UDPAddr
	mu         sync.Mutex
	conns      []net.Conn
	closeTimer *time.Timer
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*peerSession{}
)

func getOrCreateSession(password string, wgPort int) (*peerSession, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if s := sessions[password]; s != nil {
		return s, nil
	}
	localUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	s := &peerSession{
		password: password,
		localUDP: localUDP,
		wg1Addr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: wgPort},
	}
	sessions[password] = s
	go s.wgToConns()
	log.Printf("[session] created (udp %d)", localUDP.LocalAddr().(*net.UDPAddr).Port)
	return s, nil
}

// wgToConns читает ответы WG из общего localUDP и раздаёт по коннектам CHUNK'ами
// (chunked round-robin, как клиент): chunkSize пакетов подряд в один коннект,
// потом следующий — внутри TCP-окна один путь (без reorder), нагрузка по всем.
func (s *peerSession) wgToConns() {
	buf := make([]byte, 65536)
	idx, cnt := 0, 0
	for {
		n, _, err := s.localUDP.ReadFromUDP(buf)
		if err != nil {
			return // localUDP закрыт = сессия завершена
		}
		s.mu.Lock()
		conns := append([]net.Conn(nil), s.conns...)
		s.mu.Unlock()
		nc := len(conns)
		if nc == 0 {
			continue
		}
		if cnt >= chunkSize {
			cnt = 0
			idx = (idx + 1) % nc
		}
		if idx >= nc {
			idx = 0
		}
		c := conns[idx]
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, werr := c.Write(buf[:n]); werr != nil {
			// коннект сбоит — пробуем следующий, новый чанк
			if nc > 1 {
				idx = (idx + 1) % nc
				cnt = 0
				c2 := conns[idx]
				c2.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c2.Write(buf[:n])
				c2.SetWriteDeadline(time.Time{})
			}
			continue
		}
		c.SetWriteDeadline(time.Time{})
		cnt++
	}
}

func (s *peerSession) addConn(c net.Conn) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	if s.closeTimer != nil {
		s.closeTimer.Stop()
		s.closeTimer = nil
	}
	n := len(s.conns)
	s.mu.Unlock()
	log.Printf("[session] +conn (total %d)", n)
}

func (s *peerSession) removeConn(c net.Conn) {
	s.mu.Lock()
	for i, cc := range s.conns {
		if cc == c {
			s.conns = append(s.conns[:i], s.conns[i+1:]...)
			break
		}
	}
	n := len(s.conns)
	if n == 0 && s.closeTimer == nil {
		// Грейс: коннект мог отвалиться на реконнекте, новый придёт скоро.
		s.closeTimer = time.AfterFunc(20*time.Second, s.closeIfEmpty)
	}
	s.mu.Unlock()
	log.Printf("[session] -conn (total %d)", n)
}

func (s *peerSession) closeIfEmpty() {
	sessionsMu.Lock()
	s.mu.Lock()
	if len(s.conns) > 0 {
		s.mu.Unlock()
		sessionsMu.Unlock()
		return
	}
	if sessions[s.password] == s {
		delete(sessions, s.password)
	}
	s.mu.Unlock()
	sessionsMu.Unlock()
	s.localUDP.Close()
	log.Printf("[session] closed (empty)")
}
