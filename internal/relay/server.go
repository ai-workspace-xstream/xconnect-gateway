// Package relay forwards opaque peer packets over authenticated persistent
// sessions. It never decrypts the end-to-end WireGuard payload.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/pathwire"
	"net"
	"sync"
	"time"
)

type Peer struct {
	DeviceID     string   `json:"device_id"`
	PublicKey    string   `json:"public_key"`
	AllowedPeers []string `json:"allowed_peers"`
}
type Spec struct {
	Peers []Peer `json:"peers"`
}
type Config struct {
	NetworkID  string
	PrivateKey string
	ExpiresAt  time.Time
	Peers      []Peer
}
type session struct {
	c    net.Conn
	send chan pathwire.Frame
	key  []byte
	id   string
	stop sync.Once
}

func (s *session) close() { s.stop.Do(func() { s.c.Close() }) }

type Server struct {
	mu          sync.Mutex
	cfg         Config
	sessions    map[string]*session
	connections map[net.Conn]bool
	workers     sync.WaitGroup
}

func New(c Config) (*Server, error) {
	if c.NetworkID == "" || !c.ExpiresAt.After(time.Now()) || len(c.Peers) > 256 {
		return nil, errors.New("invalid relay config")
	}
	ids := map[string]bool{}
	for _, p := range c.Peers {
		if p.DeviceID == "" || ids[p.DeviceID] {
			return nil, errors.New("duplicate relay peer")
		}
		ids[p.DeviceID] = true
		if _, e := pathwire.Key(c.PrivateKey, p.PublicKey, c.NetworkID, "relay"); e != nil {
			return nil, e
		}
	}
	for _, p := range c.Peers {
		seen := map[string]bool{}
		for _, id := range p.AllowedPeers {
			if !ids[id] || id == p.DeviceID || seen[id] {
				return nil, errors.New("invalid relay grant")
			}
			seen[id] = true
		}
	}
	return &Server{cfg: c, sessions: map[string]*session{}, connections: map[net.Conn]bool{}}, nil
}
func (s *Server) Update(c Config) error {
	if _, e := New(c); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.NetworkID != s.cfg.NetworkID || c.PrivateKey != s.cfg.PrivateKey {
		return errors.New("relay identity changed")
	}
	// Close active sessions on grant/key changes. Unchanged sessions survive TTL refresh.
	for id, session := range s.sessions {
		old, new := find(s.cfg.Peers, id), find(c.Peers, id)
		if old == nil || new == nil || !same(*old, *new) {
			session.close()
		}
	}
	s.cfg = c
	return nil
}
func same(a, b Peer) bool {
	if a.PublicKey != b.PublicKey || len(a.AllowedPeers) != len(b.AllowedPeers) {
		return false
	}
	for i, v := range a.AllowedPeers {
		if v != b.AllowedPeers[i] {
			return false
		}
	}
	return true
}
func find(peers []Peer, id string) *Peer {
	for i := range peers {
		if peers[i].DeviceID == id {
			return &peers[i]
		}
	}
	return nil
}
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		l.Close()
		s.mu.Lock()
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
	}()
	defer close(done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				s.mu.Lock()
				if !s.cfg.ExpiresAt.After(time.Now()) {
					for c := range s.connections {
						c.Close()
					}
				}
				s.mu.Unlock()
			}
		}
	}()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				s.workers.Wait()
				return nil
			}
			return e
		}
		s.mu.Lock()
		if len(s.connections) >= 512 || !s.cfg.ExpiresAt.After(time.Now()) {
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.connections[c] = true
		s.mu.Unlock()
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer c.Close()
			defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
			s.handle(c)
		}()
	}
}
func (s *Server) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return
	}
	nonce := hex.EncodeToString(b[:])
	if pathwire.Write(c, pathwire.Frame{Type: "challenge", Nonce: nonce}) != nil {
		return
	}
	auth, e := pathwire.Read(c)
	if e != nil || auth.Type != "auth" || auth.Nonce != nonce {
		return
	}
	s.mu.Lock()
	cfg := s.cfg
	p := find(cfg.Peers, auth.From)
	s.mu.Unlock()
	if p == nil || auth.Network != cfg.NetworkID || !cfg.ExpiresAt.After(time.Now()) {
		return
	}
	key, e := pathwire.Key(cfg.PrivateKey, p.PublicKey, cfg.NetworkID, "relay")
	if e != nil || !pathwire.Verify(auth, key) {
		return
	}
	if pathwire.Write(c, pathwire.Sign(pathwire.Frame{Type: "welcome", Network: cfg.NetworkID, To: p.DeviceID, Nonce: nonce}, key)) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	session := &session{c: c, send: make(chan pathwire.Frame, 64), key: key, id: p.DeviceID}
	s.mu.Lock()
	current := find(s.cfg.Peers, p.DeviceID)
	if current == nil || !same(*p, *current) || !s.cfg.ExpiresAt.After(time.Now()) {
		s.mu.Unlock()
		return
	}
	if old := s.sessions[p.DeviceID]; old != nil {
		old.close()
	}
	s.sessions[p.DeviceID] = session
	s.mu.Unlock()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for f := range session.send {
			_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if pathwire.Write(c, f) != nil {
				session.close()
				return
			}
		}
	}()
	defer func() {
		session.close()
		s.mu.Lock()
		if s.sessions[p.DeviceID] == session {
			delete(s.sessions, p.DeviceID)
		}
		s.mu.Unlock()
		close(session.send)
		<-writerDone
	}()
	// Per-session token bucket bounds forwarding and candidate floods.
	tokens := float64(1024)
	last := time.Now()
	for {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, e := pathwire.Read(c)
		if e != nil {
			return
		}
		now := time.Now()
		tokens += now.Sub(last).Seconds() * 50000
		last = now
		if tokens > 1024 {
			tokens = 1024
		}
		if tokens < 1 {
			return
		}
		tokens--
		s.mu.Lock()
		current := find(s.cfg.Peers, p.DeviceID)
		if current == nil || s.sessions[p.DeviceID] != session || !s.cfg.ExpiresAt.After(now) {
			s.mu.Unlock()
			return
		}
		if f.Network != cfg.NetworkID || f.From != p.DeviceID {
			s.mu.Unlock()
			return
		}
		if f.Type == "keepalive" {
			if !pathwire.Verify(f, key) {
				s.mu.Unlock()
				return
			}
			reply := pathwire.Sign(pathwire.Frame{Type: "keepalive", Network: cfg.NetworkID, To: p.DeviceID}, key)
			select {
			case session.send <- reply:
			default:
				session.close()
			}
			s.mu.Unlock()
			continue
		}
		allowed := false
		for _, id := range current.AllowedPeers {
			if id == f.To {
				allowed = true
				break
			}
		}
		target := s.sessions[f.To]
		if allowed && target != nil && (f.Type == "data" || f.Type == "discover") && len(f.Candidates) <= 32 {
			select {
			case target.send <- f:
			default: /* bounded drop; never stall unrelated peers */
			}
		}
		s.mu.Unlock()
	}
}
