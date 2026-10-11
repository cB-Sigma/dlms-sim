package sim

import (
	"bufio"
	"io"
	"math/bits"
	"net"
	"sync"
)

// SerialPort is a meter on a simulated local serial port (an RS-485 line
// or an optical head): each Open is the head end opening the port with a
// line format, and the meter answers only in the format it runs. A
// meter on an optical port (Optical) answers the IEC 62056-21 mode E
// opening at 300 baud 7E1 and then HDLC at Baud 8N1; otherwise it serves
// HDLC at Baud with DataBits, Parity (8N1 by default) from the start.
type SerialPort struct {
	Meter    *Meter
	Baud     int    // default 9600
	DataBits int    // default 8
	Parity   string // default N
	Optical  bool
	// Ident is the identification after the "/" of a sign-on answer
	// (default "SGM5\2DLMSSIM": mode E at 9600 baud).
	Ident string

	mu       sync.Mutex
	switched bool     // the mode E option select came: the next 8N1 opening is HDLC
	opens    []string // "300 7E", "9600 8N"
	signOns  []string
	cur      net.Conn // the meter's end of the latest HDLC opening
}

// Open opens the port in a format; the meter answers only in its own.
func (p *SerialPort) Open(baud, dataBits int, parity string) (io.ReadWriteCloser, error) {
	p.Meter.prepare()
	if p.Baud == 0 {
		p.Baud = 9600
	}
	if p.DataBits == 0 {
		p.DataBits = 8
	}
	if p.Parity == "" {
		p.Parity = "N"
	}
	if p.Ident == "" {
		p.Ident = "SGM5\\2DLMSSIM"
	}
	head, meter := net.Pipe()
	p.mu.Lock()
	p.opens = append(p.opens, itoa(baud)+" "+itoa(dataBits)+parity)
	switched := p.switched
	p.switched = false
	p.mu.Unlock()
	switch {
	case p.Optical && baud == 300 && dataBits == 7 && parity == "E":
		go p.signOn(meter)
	case p.Optical && switched && baud == p.Baud && dataBits == 8 && parity == "N":
		go func() {
			defer meter.Close()
			z := p.Ident[3]
			confirm := []byte{0x06, '2', z, '2', '\r', '\n'}
			for i, b := range confirm { // 7E1 characters read as 8N1
				if bits.OnesCount8(b)%2 == 1 {
					confirm[i] = b | 0x80
				}
			}
			if _, err := meter.Write(confirm); err != nil {
				return
			}
			_ = p.Meter.ServeHDLC(meter)
		}()
	case !p.Optical && baud == p.Baud && dataBits == p.DataBits && parity == p.Parity:
		p.mu.Lock()
		p.cur = meter
		p.mu.Unlock()
		go func() { defer meter.Close(); _ = p.Meter.ServeHDLC(meter) }()
	default:
		go func() { _, _ = io.Copy(io.Discard, meter) }() // wrong format: nothing intelligible
	}
	return head, nil
}

// signOn answers the sign-on and takes the option select.
func (p *SerialPort) signOn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	req, err := r.ReadString('\n')
	if err != nil || len(req) < 5 || req[:2] != "/?" {
		return
	}
	p.mu.Lock()
	p.signOns = append(p.signOns, req)
	p.mu.Unlock()
	if _, err := c.Write([]byte("/" + p.Ident + "\r\n")); err != nil {
		return
	}
	sel := make([]byte, 6)
	if _, err := io.ReadFull(r, sel); err != nil {
		return
	}
	if sel[0] == 0x06 && sel[1] == '2' && sel[3] == '2' {
		p.mu.Lock()
		p.switched = true
		p.mu.Unlock()
	}
}

// Opens lists the formats the port was opened with ("300 7E").
func (p *SerialPort) Opens() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.opens...)
}

// SignOns lists the sign-on requests received.
func (p *SerialPort) SignOns() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.signOns...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// PushHDLC sends the meter's push on the open line as HDLC UI frames
// (HDLCFrames), as a meter on an RS-485 push line does.
func (p *SerialPort) PushHDLC(setupOBIS string, maxInfo int) error {
	p.mu.Lock()
	c := p.cur
	p.mu.Unlock()
	if c == nil {
		return io.ErrClosedPipe
	}
	apdu, err := p.Meter.pushAPDU(setupOBIS)
	if err != nil {
		return err
	}
	for _, f := range HDLCFrames(p.Meter.pushClient(), cat([]byte{0xE6, 0xE7, 0x00}, apdu), maxInfo) {
		if _, err := c.Write(f); err != nil {
			return err
		}
	}
	return nil
}
