package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGManager manages dynamic WireGuard peers on a named interface.
type WGManager struct {
	mu        sync.Mutex
	iface     string
	serverIP  string // e.g. "10.66.66.1"
	ipPool    []string
	usedIPs   map[string]bool
}

func NewWGManager(iface string, serverIP string, subnetCIDR string) (*WGManager, error) {
	_, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}

	var pool []string
	for ip := incrementIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); ip = incrementIP(ip) {
		s := ip.String()
		if s == serverIP {
			continue
		}
		pool = append(pool, s)
	}
	if len(pool) == 0 {
		return nil, fmt.Errorf("empty IP pool")
	}

	return &WGManager{
		iface:    iface,
		serverIP: serverIP,
		ipPool:   pool,
		usedIPs:  make(map[string]bool),
	}, nil
}

func incrementIP(ip net.IP) net.IP {
	ip = append(net.IP{}, ip...) // copy
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip
}

// GenerateKeyPair generates a WireGuard private+public key pair.
// Returns (privateKeyBase64, publicKeyBase64, error).
func (m *WGManager) GenerateKeyPair() (string, string, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	pub := priv.PublicKey()
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:]),
		nil
}

// AllocateIP picks a free IP from the pool.
func (m *WGManager) AllocateIP() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range m.ipPool {
		if !m.usedIPs[ip] {
			m.usedIPs[ip] = true
			return ip, nil
		}
	}
	return "", fmt.Errorf("IP pool exhausted")
}

// FreeIP returns an IP to the pool.
func (m *WGManager) FreeIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.usedIPs, ip)
}

// MarkIPUsed marks an IP as in use (for restoring from store on startup).
func (m *WGManager) MarkIPUsed(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usedIPs[ip] = true
}

// AddPeer registers a WireGuard peer via `wg set`.
func (m *WGManager) AddPeer(pubKeyB64, clientIP string) error {
	out, err := exec.Command("wg", "set", m.iface,
		"peer", pubKeyB64,
		"allowed-ips", clientIP+"/32",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set peer: %v — %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[wg] added peer %s... ip=%s", pubKeyB64[:8], clientIP)
	return nil
}

// RemovePeer removes a WireGuard peer via `wg set`.
func (m *WGManager) RemovePeer(pubKeyB64 string) error {
	out, err := exec.Command("wg", "set", m.iface,
		"peer", pubKeyB64,
		"remove",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg remove peer: %v — %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[wg] removed peer %s...", pubKeyB64[:8])
	return nil
}

// SyncPeers ensures all known entries have their WG peers registered.
// Called on startup to restore state from the password store.
func (m *WGManager) SyncPeers(store *PasswordStore) {
	store.mu.RLock()
	entries := make(map[string]*PasswordEntry, len(store.entries))
	for p, e := range store.entries {
		entries[p] = e
	}
	store.mu.RUnlock()

	for _, e := range entries {
		if e == nil {
			continue
		}
		m.MarkIPUsed(e.ClientIP)
		if err := m.AddPeer(e.WGPublicKey, e.ClientIP); err != nil {
			log.Printf("[wg] sync peer failed: %v", err)
		}
	}
	log.Printf("[wg] synced %d peers", len(entries))
}

// ServerPublicKey reads the server's WG public key via `wg show <iface> public-key`.
func (m *WGManager) ServerPublicKey() (string, error) {
	out, err := exec.Command("wg", "show", m.iface, "public-key").Output()
	if err != nil {
		return "", fmt.Errorf("wg show public-key: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
