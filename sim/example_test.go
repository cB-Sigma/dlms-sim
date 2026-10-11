// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/wrapper"
)

// getSerial is a GET of the meter serial number (class 1, 0.0.96.1.0.255,
// attribute 2).
func getSerial() []byte {
	b, err := gdlms.CreateGetRequestNormal(1, *gdlms.CreateAttributeDescriptor(1, "0.0.96.1.0.255", 2), nil).Encode()
	if err != nil {
		panic(err)
	}
	return b
}

// value decodes the data of a get-response-normal.
func value(resp []byte) any {
	r, err := gdlms.DecodeGetResponseNormal(&resp)
	if err != nil {
		return err
	}
	d, ok := r.Result.Value.(axdr.DlmsData)
	if !ok {
		return r.Result.Value
	}
	// gosem gives an octet-string as hex.
	if h, ok := d.Value.(string); ok {
		if b, err := hex.DecodeString(h); err == nil {
			return string(b)
		}
	}
	return d.Value
}

// An IS 15959 Part 2 single-phase meter served over the wrapper on TCP:
// the public client (16) associates without authentication and reads the
// meter serial number.
func Example() {
	sp, _ := is15959.Get("part2-1ph")
	m := sim.NewIS15959(sp, sim.IS15959Options{Serial: "00001401"})
	addr, err := m.Listen("127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer m.Close()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	exchange := func(apdu []byte) []byte {
		w, _ := wrapper.Encode(16, 1, apdu)
		if _, err := c.Write(w); err != nil {
			panic(err)
		}
		_, resp, err := wrapper.ReadWPDU(c)
		if err != nil {
			panic(err)
		}
		return resp
	}
	settings, _ := gdlms.NewSettingsWithoutAuthentication()
	aarq, _ := gdlms.EncodeAARQ(&settings)
	aare := exchange(aarq)
	res, err := gdlms.DecodeAARE(&settings, &aare)
	fmt.Println("association:", res.AssociationResult, err)
	fmt.Println("serial number:", value(exchange(getSerial())))
	// Output:
	// association: 0 <nil>
	// serial number: 00001401
}

// The meter behind a transport of the caller's own: APDUs in, APDUs out.
func ExampleMeter_HandleAPDU() {
	sp, _ := is15959.Get("part2-1ph")
	m := sim.NewIS15959(sp, sim.IS15959Options{Serial: "00001401"})
	m.Prepare()
	s := m.NewSession(16)
	settings, _ := gdlms.NewSettingsWithoutAuthentication()
	aarq, _ := gdlms.EncodeAARQ(&settings)
	aare := m.HandleAPDU(s, aarq)
	res, err := gdlms.DecodeAARE(&settings, &aare)
	fmt.Println("association:", res.AssociationResult, err)
	fmt.Println("serial number:", value(m.HandleAPDU(s, getSerial())))
	fmt.Println("serves wPort 1:", m.ServesWPort(1), "wPort 2:", m.ServesWPort(2))
	// Output:
	// association: 0 <nil>
	// serial number: 00001401
	// serves wPort 1: true wPort 2: false
}
