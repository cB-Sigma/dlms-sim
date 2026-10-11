package iec6205621sim

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	p "github.com/cB-Sigma/dlms/iec6205621"
)

// Line is several meters on one serial line behind one transparent
// converter (an RS-485 bus or a daisy chain of meters sharing a port):
// every connection reaches every meter, and the one whose address the
// sign-on names answers. Two masters' sessions open at once would mix on
// the wire; the line counts them (Overlaps) instead of garbling them.
type Line struct {
	mu       sync.Mutex
	meters   []*Meter
	ln       net.Listener
	addr     string
	active   int
	overlaps int
}

// NewLine puts meters on one line.
func NewLine(meters ...*Meter) *Line {
	return &Line{meters: meters}
}

// Listen starts accepting on 127.0.0.1.
func (l *Line) Listen() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.ln, l.addr = ln, ln.Addr().String()
	l.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go l.serve(c)
		}
	}()
	return nil
}

// Addr is the listening address.
func (l *Line) Addr() string { l.mu.Lock(); defer l.mu.Unlock(); return l.addr }

// Stop closes the listener.
func (l *Line) Stop() { l.mu.Lock(); defer l.mu.Unlock(); _ = l.ln.Close() }

// Overlaps is how many sessions began while another was still open.
func (l *Line) Overlaps() int { l.mu.Lock(); defer l.mu.Unlock(); return l.overlaps }

func (l *Line) serve(c net.Conn) {
	l.mu.Lock()
	// A master that closed its last connection just before dialling again
	// is not an overlap: allow the close a moment to arrive.
	deadline := time.Now().Add(300 * time.Millisecond)
	for l.active > 0 && time.Now().Before(deadline) {
		l.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		l.mu.Lock()
	}
	if l.active > 0 {
		l.overlaps++
	}
	l.active++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.active--
		l.mu.Unlock()
	}()
	r := bufio.NewReader(c)
	// The first request names the meter.
	var head []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			_ = c.Close()
			return
		}
		head = append(head, b)
		if b&0x7f == p.LF || len(head) > 200 {
			break
		}
	}
	var req strings.Builder
	for _, b := range head {
		if b &= 0x7f; b != 0 && b != '\r' && b != '\n' {
			req.WriteByte(b)
		}
	}
	s := req.String()
	var to *Meter
	if strings.HasPrefix(s, "/?") && strings.HasSuffix(s, "!") {
		for _, m := range l.meters {
			m.mu.Lock()
			a := m.Address
			m.mu.Unlock()
			if p.SameAddress(s[2:len(s)-1], a) {
				if to != nil {
					// Several meters answer: their identifications collide.
					l.mu.Lock()
					l.overlaps++
					l.mu.Unlock()
					_ = c.Close()
					return
				}
				to = m
			}
		}
	}
	if to == nil {
		_ = c.Close()
		return
	}
	to.serve(&prefixConn{Conn: c, r: io.MultiReader(strings.NewReader(string(head)), r)})
}

// prefixConn reads bytes already taken from the connection first.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }
