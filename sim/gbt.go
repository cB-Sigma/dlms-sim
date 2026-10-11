package sim

import (
	"encoding/binary"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// GBTLink is the meter side of general block transfer (xDLMS
// general-block-transfer, tag E0h; IEC 62056-5-3:2023 7.3.13) on a
// request/answer link such as M-Bus, written apart from package dlms: the
// client's blocks are acknowledged one by one (an empty block, last-block
// clear) and joined; an answer longer than Size goes back as blocks, the
// next one sent for each acknowledgement. Block numbers rise with every
// GBT APDU the meter sends. A zero Size answers whole.
type GBTLink struct {
	Size int

	in      []byte
	inNext  uint16 // client's next data block (0: none started)
	num     uint16 // our last block number
	lastIn  uint16 // client's last block number
	out     [][]byte
	sentOut int
	// Received and Sent count the data blocks of the last exchange.
	Received, Sent int
}

func gbtBlock(last bool, num, ack uint16, data []byte) []byte {
	ctrl := byte(0x01)
	if last {
		ctrl |= 0x80
	}
	b := []byte{0xE0, ctrl, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], num)
	binary.BigEndian.PutUint16(b[4:], ack)
	l, _ := axdr.EncodeLength(len(data))
	return cat(b, l, data)
}

// Handle takes what the client sent (as on the wire, still protected) and
// returns the meter's answer; serve answers one whole APDU.
func (g *GBTLink) Handle(w []byte, serve func([]byte) []byte) []byte {
	if len(w) == 0 || w[0] != 0xE0 {
		g.reset()
		return g.answer(serve(w))
	}
	if len(w) < 7 {
		return nil
	}
	ctrl := w[1]
	n := binary.BigEndian.Uint16(w[2:4])
	l, sz := readLen(w[6:])
	if l < 0 || 6+sz+l != len(w) {
		return nil
	}
	data := w[6+sz:]
	g.lastIn = n
	if g.sentOut > 0 && g.sentOut < len(g.out) && len(data) == 0 {
		return g.nextOut() // the client acknowledged our block
	}
	if g.inNext == 0 {
		if g.sentOut > 0 {
			g.out, g.sentOut = nil, 0
		}
		g.inNext, g.Received, g.num = n, 0, 0
	}
	if n != g.inNext {
		g.reset()
		return nil
	}
	g.in = append(g.in, data...)
	g.inNext++
	g.Received++
	if ctrl&0x80 == 0 {
		g.num++
		return gbtBlock(false, g.num, n, nil)
	}
	apdu := g.in
	g.in, g.inNext = nil, 0
	return g.answer(serve(apdu))
}

func (g *GBTLink) reset() {
	g.in, g.inNext, g.out, g.sentOut, g.Received, g.Sent, g.num = nil, 0, nil, 0, 0, 0, 0
}

// answer sends an answer whole or starts it in blocks.
func (g *GBTLink) answer(resp []byte) []byte {
	g.Sent = 0
	if g.Size <= 0 || len(resp) <= g.Size {
		return resp
	}
	g.out, g.sentOut = nil, 0
	for len(resp) > g.Size {
		g.out = append(g.out, resp[:g.Size])
		resp = resp[g.Size:]
	}
	g.out = append(g.out, resp)
	return g.nextOut()
}

func (g *GBTLink) nextOut() []byte {
	d := g.out[g.sentOut]
	g.sentOut++
	g.num++
	g.Sent++
	return gbtBlock(g.sentOut == len(g.out), g.num, g.lastIn, d)
}
