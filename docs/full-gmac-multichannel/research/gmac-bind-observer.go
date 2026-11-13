// Copyright (C)2016 - SMBJ Contributors
// Licensed under the Apache License, Version 2.0.
// Diagnostic only: successful binding is not evidence of GMAC nonce safety.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
)

// Observe socket bytes outside both donor signing and verification code.
// Raw packets and keys stay in memory; output contains keyed fingerprints only.
type event struct {
	ID          int    `json:"event_id"`
	Connection  int    `json:"connection"`
	FromServer  bool   `json:"from_server"`
	Command     uint16 `json:"command"`
	Status      uint32 `json:"status"`
	MID         uint64 `json:"message_id"`
	Credits     uint16 `json:"credits"`
	Signed      bool   `json:"signed"`
	Length      int    `json:"length"`
	KeyRole     string `json:"key_role,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	Fingerprint string `json:"message_fingerprint"`
	Verified    bool   `json:"independently_verified,omitempty"`
	Reuses      int    `json:"different_message_reusing_event,omitempty"`
	wire        []byte
}

type observer struct {
	mu     sync.Mutex
	salt   [32]byte
	events []*event
	err    error
}

type observedConn struct {
	net.Conn
	owner   *observer
	id      int
	pending [2][]byte
	hash    [64]byte
	context [64]byte
	key     []byte
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.observe(1, p[:n])
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.observe(0, p[:n])
	return n, err
}

func (o *observer) fingerprint(p []byte) string {
	h := hmac.New(sha256.New, o.salt[:])
	h.Write(p)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *observedConn) observe(direction int, data []byte) {
	o := c.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return
	}
	c.pending[direction] = append(c.pending[direction], data...)
	for len(c.pending[direction]) >= 4 {
		p := c.pending[direction]
		size := int(binary.BigEndian.Uint32(p[:4]))
		if size < 64 || size > 1<<20 {
			o.err = errors.New("observer: invalid or oversized diagnostic frame")
			return
		}
		if len(p) < size+4 {
			return
		}
		wire := bytes.Clone(p[4 : size+4])
		c.pending[direction] = p[size+4:]
		if !bytes.Equal(wire[:4], []byte{0xfe, 'S', 'M', 'B'}) {
			o.err = errors.New("observer: expected plaintext SMB2 diagnostic traffic")
			return
		}
		flags := binary.LittleEndian.Uint32(wire[16:20])
		if (flags&1 != 0) != (direction == 1) {
			o.err = errors.New("observer: sender role disagrees with socket direction")
			return
		}
		e := &event{ID: len(o.events) + 1, Connection: c.id, FromServer: direction == 1,
			Command: binary.LittleEndian.Uint16(wire[12:14]), Status: binary.LittleEndian.Uint32(wire[8:12]),
			MID: binary.LittleEndian.Uint64(wire[24:32]), Credits: binary.LittleEndian.Uint16(wire[14:16]),
			Signed: flags&8 != 0, Length: size, wire: wire}
		normalized := bytes.Clone(wire)
		clear(normalized[48:64])
		e.Fingerprint = o.fingerprint(normalized)
		o.events = append(o.events, e)
		if e.Command == 0 && e.FromServer {
			if err := selectedGMAC(wire); err != nil {
				o.err = err
				return
			}
		}
		if e.Command == 0 || e.Command == 1 {
			if e.Command == 1 && e.FromServer && e.Status == 0 {
				c.context = c.hash // KDF covers the final request, not this response.
			}
			h := sha512.New()
			h.Write(c.hash[:])
			h.Write(wire)
			copy(c.hash[:], h.Sum(nil))
		}
	}
}

func selectedGMAC(wire []byte) error {
	if len(wire) < 128 || binary.LittleEndian.Uint16(wire[68:70]) != 0x311 {
		return errors.New("observer: SMB 3.1.1 was not selected")
	}
	count := int(binary.LittleEndian.Uint16(wire[70:72]))
	offset := int(binary.LittleEndian.Uint32(wire[124:128]))
	for range count {
		if offset < 128 || offset > len(wire)-8 {
			return errors.New("observer: malformed negotiate context header")
		}
		typeID := binary.LittleEndian.Uint16(wire[offset : offset+2])
		length := int(binary.LittleEndian.Uint16(wire[offset+2 : offset+4]))
		if length > len(wire)-offset-8 {
			return errors.New("observer: malformed negotiate context data")
		}
		if typeID == 8 {
			p := wire[offset+8 : offset+8+length]
			if len(p) == 4 && binary.LittleEndian.Uint16(p[:2]) == 1 && binary.LittleEndian.Uint16(p[2:]) == 2 {
				return nil
			}
			return errors.New("observer: AES-GMAC was not selected")
		}
		offset += (length + 15) &^ 7
	}
	return errors.New("observer: no signing capabilities response")
}

func signingKey(gssKey []byte, transcript [64]byte) []byte {
	key := make([]byte, 16)
	copy(key, gssKey)
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0, 0, 0, 1})
	h.Write([]byte("SMBSigningKey\x00\x00"))
	h.Write(transcript[:])
	h.Write([]byte{0, 0, 0, 128})
	return h.Sum(nil)[:16]
}

func (o *observer) verify(connections []*observedConn) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return 0, o.err
	}
	seen := make(map[string]*event)
	collisions := 0
	for _, e := range o.events {
		if !e.Signed {
			continue
		}
		key := connections[e.Connection].key
		e.KeyRole = "channel"
		if e.Connection == 0 || (e.Command == 1 && (!e.FromServer || e.Status != 0)) {
			key = connections[0].key
			e.KeyRole = "original-session"
		}
		if len(key) != 16 {
			return 0, errors.New("observer: missing actual signing key")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return 0, err
		}
		gmac, err := cipher.NewGCM(block)
		if err != nil {
			return 0, err
		}
		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce, e.MID)
		if e.FromServer {
			nonce[8] = 1
		}
		if e.Command == 12 {
			nonce[8] |= 2
		}
		normalized := bytes.Clone(e.wire)
		clear(normalized[48:64])
		if !hmac.Equal(gmac.Seal(nil, nonce, nil, normalized), e.wire[48:64]) {
			return 0, fmt.Errorf("observer: event %d failed independent GMAC verification", e.ID)
		}
		e.Verified, e.KeyID, e.Nonce = true, o.fingerprint(key), hex.EncodeToString(nonce)
		domain := e.KeyID + ":" + e.Nonce
		if previous := seen[domain]; previous != nil && previous.Fingerprint != e.Fingerprint {
			e.Reuses = previous.ID
			collisions++
		} else {
			seen[domain] = e
		}
	}
	return collisions, nil
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	o := &observer{}
	if _, err := rand.Read(o.salt[:]); err != nil {
		return err
	}
	var connections []*observedConn
	defer func() {
		for _, c := range connections {
			_ = c.Close()
		}
	}()
	connect := func() (*observedConn, error) {
		raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:36531")
		if err != nil {
			return nil, err
		}
		c := &observedConn{Conn: raw, owner: o, id: len(connections)}
		connections = append(connections, c)
		return c, nil
	}
	domain := "WORKGROUP"
	credential := auth.NTLMCredential{User: "smbtest", Password: "TestOnly123!", Domain: &domain}
	primary, err := connect()
	if err != nil {
		return err
	}
	initiator, err := credential.NewInitiator(ctx, "localhost")
	if err != nil {
		return err
	}
	session, err := (&protocol.Dialer{SpecifiedDialects: []protocol.Dialect{protocol.SMB311}, RequireMessageSigning: true}).Dial(ctx, initiator, protocol.NewTransport(primary))
	if err != nil {
		return err
	}
	primary.key = signingKey(initiator.SessionKey(), primary.context)
	if err := session.Echo(ctx); err != nil {
		return err
	}
	for range 2 {
		secondary, err := connect()
		if err != nil {
			return err
		}
		initiator, err := credential.NewInitiator(ctx, "localhost")
		if err != nil {
			return err
		}
		if err := session.BindChannel(ctx, initiator, protocol.NewTransport(secondary)); err != nil {
			return err
		}
		secondary.key = signingKey(initiator.SessionKey(), secondary.context)
		if err := session.Echo(ctx); err != nil {
			return err
		}
	}
	if err := session.Close(); err != nil {
		return err
	}
	collisions, err := o.verify(connections)
	if err != nil {
		return err
	}
	if collisions == 0 {
		return errors.New("observer: no collision observed; this is not a safety proof")
	}
	report := struct {
		Result     string   `json:"result"`
		Bindings   int      `json:"successful_legitimate_bindings"`
		Collisions int      `json:"verified_different_message_key_nonce_reuses"`
		Events     []*event `json:"events"`
	}{"NONCE_REUSE_CONFIRMED", 2, collisions, o.events}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "GMAC research diagnostic:", err)
		os.Exit(1)
	}
}
