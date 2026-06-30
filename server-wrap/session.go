package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// peerSession агрегирует НЕСКОЛЬКО DTLS-коннектов одного пароля в ОДИН WG-прокси.
// Все коннекты делят общий localUDP↔wg1 (wg1 видит один эндпоинт, не «прыгает»).
// Ответы WG раздаются по ЖИВЫМ коннектам chunked round-robin'ом. Это даёт мультипоток:
// клиент гонит WG по N потокам, любой живой несёт трафик, мёртвый исключается.
// chunkSize — пакетов подряд в один коннект перед переключением (как у клиента).
const chunkSize = 8

// aliveWindow — коннект считается живым, если входящее (WG-данные ИЛИ PONG) было
// не позже этого окна. Сервер пингует каждый коннект каждые 20с → живой клиент
// шлёт PONG → lastIn обновляется. Мёртвый relay (реконнект клиента) молчит →
// за 40с выпадает из раздачи download'а. Это не даёт слать WG-ответы (в т.ч.
// единственный пакет handshake) в мёртвый путь — корень бага «RX=0 не поднимается».
const aliveWindow = 40 * time.Second

// sessConn — коннект внутри сессии с меткой последнего входящего пакета.
type sessConn struct {
	conn   net.Conn
	lastIn atomic.Int64 // unix-nano последнего входящего от клиента
}

func (sc *sessConn) touch() { sc.lastIn.Store(time.Now().UnixNano()) }

func (sc *sessConn) alive() bool {
	last := sc.lastIn.Load()
	return last != 0 && time.Since(time.Unix(0, last)) <= aliveWindow
}

type peerSession struct {
	password   string
	localUDP   *net.UDPConn
	wg1Addr    *net.UDPAddr
	mu         sync.Mutex
	conns      []*sessConn
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

// wgToConns читает ответы WG из общего localUDP и раздаёт по ЖИВЫМ коннектам
// CHUNK'ами (chunked round-robin, как клиент): chunkSize пакетов подряд в один
// коннект, потом следующий — внутри TCP-окна один путь (без reorder), нагрузка по
// всем живым. Мёртвые (молчащие >aliveWindow) исключаются — WG-ответы (включая
// одиночный handshake) не уходят в дохлый relay.
func (s *peerSession) wgToConns() {
	buf := make([]byte, 65536)
	idx, cnt := 0, 0
	for {
		n, _, err := s.localUDP.ReadFromUDP(buf)
		if err != nil {
			return // localUDP закрыт = сессия завершена
		}

		// Снимок только ЖИВЫХ коннектов. Если живых нет (холодный старт, ещё ни
		// одного входящего) — фолбэк на все, чтобы handshake точно прошёл.
		s.mu.Lock()
		alive := make([]*sessConn, 0, len(s.conns))
		for _, sc := range s.conns {
			if sc.alive() {
				alive = append(alive, sc)
			}
		}
		if len(alive) == 0 {
			alive = append(alive, s.conns...)
		}
		s.mu.Unlock()

		nc := len(alive)
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
		c := alive[idx].conn
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, werr := c.Write(buf[:n]); werr != nil {
			// коннект сбоит — пробуем следующий живой, новый чанк
			if nc > 1 {
				idx = (idx + 1) % nc
				cnt = 0
				c2 := alive[idx].conn
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

// addConn добавляет коннект и возвращает обёртку sessConn (handleConn обновляет
// её lastIn на каждом входящем — это держит коннект «живым» для раздачи download).
func (s *peerSession) addConn(c net.Conn) *sessConn {
	sc := &sessConn{conn: c}
	sc.touch() // только что подключился — считаем живым
	s.mu.Lock()
	s.conns = append(s.conns, sc)
	if s.closeTimer != nil {
		s.closeTimer.Stop()
		s.closeTimer = nil
	}
	n := len(s.conns)
	s.mu.Unlock()
	log.Printf("[session] +conn (total %d)", n)
	return sc
}

func (s *peerSession) removeConn(sc *sessConn) {
	s.mu.Lock()
	for i, cc := range s.conns {
		if cc == sc {
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
