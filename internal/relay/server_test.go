package relay

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"github.com/ai-workspace-xstream/XConnect-Gateway/internal/pathwire"
	"net"
	"testing"
	"time"
)

func TestRelayRejectsBadProofNetworkAndForgedSessionIdentity(t *testing.T) {
	gateway, _ := ecdh.X25519().GenerateKey(rand.Reader)
	one, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encode := base64.StdEncoding.EncodeToString
	server, e := New(Config{NetworkID: "net", PrivateKey: encode(gateway.Bytes()), ExpiresAt: time.Now().Add(time.Minute), Peers: []Peer{{DeviceID: "one", PublicKey: encode(one.PublicKey().Bytes())}}})
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	key, e := pathwire.Key(encode(one.Bytes()), encode(gateway.PublicKey().Bytes()), "net", "relay")
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"proof", "network", "identity"} {
		t.Run(mode, func(t *testing.T) {
			c, e := net.Dial("tcp", listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			challenge, e := pathwire.Read(c)
			if e != nil {
				t.Fatal(e)
			}
			auth := pathwire.Frame{Type: "auth", Network: "net", From: "one", Nonce: challenge.Nonce}
			if mode == "network" {
				auth.Network = "other"
			}
			auth = pathwire.Sign(auth, key)
			if mode == "proof" {
				auth.MAC[0] ^= 1
			}
			if e = pathwire.Write(c, auth); e != nil {
				t.Fatal(e)
			}
			welcome, e := pathwire.Read(c)
			if mode != "identity" {
				if e == nil {
					t.Fatal("unauthorized session accepted")
				}
				return
			}
			if e != nil || welcome.Type != "welcome" || !pathwire.Verify(welcome, key) {
				t.Fatal("legitimate session rejected", e)
			}
			if e = pathwire.Write(c, pathwire.Frame{Type: "data", Network: "net", From: "another-device", To: "one"}); e != nil {
				t.Fatal(e)
			}
			if _, e = pathwire.Read(c); e == nil {
				t.Fatal("forged identity retained session")
			}
		})
	}
}
