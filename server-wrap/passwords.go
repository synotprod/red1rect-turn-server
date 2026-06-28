package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

// PasswordEntry holds per-password WireGuard peer data.
type PasswordEntry struct {
	WGPrivateKey string `json:"wg_private_key"` // client private key (base64)
	WGPublicKey  string `json:"wg_public_key"`  // client public key (base64)
	ClientIP     string `json:"client_ip"`       // e.g. "10.66.66.5"
}

// PasswordStore maps password → PasswordEntry.
// It persists to a JSON file on disk so peers survive server restarts.
type PasswordStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]*PasswordEntry // password → entry
}

type storeFile struct {
	Passwords map[string]*PasswordEntry `json:"passwords"`
}

func NewPasswordStore(path string) (*PasswordStore, error) {
	ps := &PasswordStore{
		path:    path,
		entries: make(map[string]*PasswordEntry),
	}
	if err := ps.load(); err != nil {
		return nil, err
	}
	return ps, nil
}

func (ps *PasswordStore) load() error {
	data, err := os.ReadFile(ps.path)
	if os.IsNotExist(err) {
		return nil // fresh start
	}
	if err != nil {
		return fmt.Errorf("read store: %w", err)
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse store: %w", err)
	}
	if f.Passwords != nil {
		ps.entries = f.Passwords
	}
	log.Printf("[store] loaded %d passwords from %s", len(ps.entries), ps.path)
	return nil
}

func (ps *PasswordStore) save() error {
	f := storeFile{Passwords: ps.entries}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ps.path, data, 0600)
}

// Get returns entry for password (nil if not found).
func (ps *PasswordStore) Get(password string) *PasswordEntry {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.entries[password]
}

// GetOrCreate returns existing entry or creates new WG peer for this password.
func (ps *PasswordStore) GetOrCreate(password string, mgr *WGManager) (*PasswordEntry, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if e, ok := ps.entries[password]; ok {
		return e, nil
	}

	// Generate new WG keypair for this password.
	privKey, pubKey, err := mgr.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	ip, err := mgr.AllocateIP()
	if err != nil {
		return nil, fmt.Errorf("alloc ip: %w", err)
	}

	entry := &PasswordEntry{
		WGPrivateKey: privKey,
		WGPublicKey:  pubKey,
		ClientIP:     ip,
	}
	ps.entries[password] = entry
	if err := ps.save(); err != nil {
		log.Printf("[store] save error: %v", err)
	}
	log.Printf("[store] new entry for password (ip=%s pubkey=%s...)", ip, pubKey[:8])
	return entry, nil
}

// AddPassword adds a password with no WG peer yet (peer created on first connect).
func (ps *PasswordStore) AddPassword(password string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, ok := ps.entries[password]; !ok {
		ps.entries[password] = nil // placeholder, peer created on connect
		_ = ps.save()
		log.Printf("[store] added password")
	}
}

// RemovePassword removes a password and its WG peer.
func (ps *PasswordStore) RemovePassword(password string, mgr *WGManager) {
	ps.mu.Lock()
	e := ps.entries[password]
	delete(ps.entries, password)
	_ = ps.save()
	ps.mu.Unlock()

	if e != nil {
		if err := mgr.RemovePeer(e.WGPublicKey); err != nil {
			log.Printf("[store] remove peer: %v", err)
		}
		mgr.FreeIP(e.ClientIP)
	}
}

// Has checks if password exists in store (even with nil entry = pre-registered).
func (ps *PasswordStore) Has(password string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	_, ok := ps.entries[password]
	return ok
}

// StartAPI starts HTTP API on the given address for backend to manage passwords.
//
// POST   /api/password  {"password":"xxx"}  — add password
// DELETE /api/password  {"password":"xxx"}  — remove password
// GET    /api/passwords                      — list all passwords
func (ps *PasswordStore) StartAPI(addr string, mgr *WGManager) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/password", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
			http.Error(w, "bad request", 400)
			return
		}
		switch r.Method {
		case http.MethodPost:
			ps.AddPassword(body.Password)
			w.WriteHeader(204)
		case http.MethodDelete:
			ps.RemovePassword(body.Password, mgr)
			w.WriteHeader(204)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})

	mux.HandleFunc("/api/passwords", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		ps.mu.RLock()
		list := make([]string, 0, len(ps.entries))
		for p := range ps.entries {
			list = append(list, p)
		}
		ps.mu.RUnlock()
		json.NewEncoder(w).Encode(list)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[api] listen %s: %v", addr, err)
		return
	}
	log.Printf("[api] listening on %s", addr)
	go http.Serve(ln, mux)
}
