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
type peerSession struct {
	password   string
	localUDP   *net.UDPConn
	wg1Addr    *net.UDPAddr
	mu         sync.Mutex
	conns      []net.Conn
	closeTimer *time.Timer

	// activeConn — коннект, ПОСЛЕДНИМ приславший WG-данные. Клиент шлёт WG через
	// один активный поток (active/standby, без reordering); ответы WG возвращаем
	// в него же. На фейловере клиент переключит поток → сменится active.
	activeMu   sync.Mutex
	activeConn net.Conn
}

func (s *peerSession) setActive(c net.Conn) {
	s.activeMu.Lock()
	s.activeConn = c
	s.activeMu.Unlock()
}

func (s *peerSession) getActive() net.Conn {
	s.activeMu.Lock()
	c := s.activeConn
	s.activeMu.Unlock()
	return c
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

// wgToConns читает ответы WG из общего localUDP и шлёт в АКТИВНЫЙ коннект (тот,
// что последним прислал WG-данные). Это active/standby — без reordering. Если
// активный мёртв/не задан — фолбэк на любой живой.
func (s *peerSession) wgToConns() {
	buf := make([]byte, 65536)
	for {
		n, _, err := s.localUDP.ReadFromUDP(buf)
		if err != nil {
			return // localUDP закрыт = сессия завершена
		}
		c := s.getActive()
		if c == nil || !s.hasConn(c) {
			c = s.pickConn()
		}
		if c == nil {
			continue
		}
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, werr := c.Write(buf[:n]); werr != nil {
			if c2 := s.pickConn(); c2 != nil && c2 != c {
				c2.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c2.Write(buf[:n])
				c2.SetWriteDeadline(time.Time{})
			}
			continue
		}
		c.SetWriteDeadline(time.Time{})
	}
}

func (s *peerSession) hasConn(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cc := range s.conns {
		if cc == c {
			return true
		}
	}
	return false
}

// pickConn — любой живой коннект (фолбэк когда активный не задан/мёртв).
func (s *peerSession) pickConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) == 0 {
		return nil
	}
	return s.conns[0]
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
