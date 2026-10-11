// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"fmt"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms-sim/sim"
	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/wrapper"
)

// A client of the dlms module with HLS-GMAC (mechanism 5) and
// authenticated and encrypted APDUs under a dedicated key reads a voltage
// register from the simulator, over the wrapper on TCP. The meter's frame
// counter for the client is read first through the public client, so the
// association starts past it.
func Example_cosemClient() {
	key := []byte("0123456789ABCDEF")
	ak := []byte("FEDCBA9876543210")
	meter := &sim.Meter{HLS: &sim.HLS{Policy: 0x30, SystemTitle: []byte("SIM\x00\x00\x00\x00\x01"),
		Key: key, AuthKey: ak, FrameCounterOBIS: "0.0.43.1.3.255"}}
	meter.Register("1.0.32.7.0.255", axdr.CreateAxdrLongUnsigned(23050), -2, 35) // 230.50 V
	meter.Set(1, "0.0.43.1.3.255", 2, axdr.CreateAxdrDoubleLongUnsigned(41))
	addr, err := meter.Listen("127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer meter.Close()

	sec := cosem.SecurityConfig{Name: "M1", Authentication: "hls-gmac", Security: "authenticated-encrypted",
		BlockCipherKey: fmt.Sprintf("%X", key), AuthenticationKey: fmt.Sprintf("%X", ak), DedicatedKey: true}
	hls, _, err := sec.Build()
	if err != nil {
		panic(err)
	}
	c := cosem.NewClient(cosem.ClientConfig{
		Transport: func(client int) (gdlms.Transport, error) {
			return wrapper.New("tcp", addr, client, 1, 5*time.Second)
		},
		ClientAddress:     cosem.DefaultClientAddress(cosem.MechGMAC), // 48
		HLS:               hls,
		InvocationCounter: &cosem.FrameCounterObject{OBIS: "0.0.43.1.3.255"},
		Name:              "M1", Where: addr,
	})
	if err := c.Connect(); err != nil {
		panic(err)
	}
	defer c.Close()
	v, err := c.Get(3, "1.0.32.7.0.255", 2)
	if err != nil {
		panic(err)
	}
	s, err := cosem.ReadScaler(c.Association().Client, 3, "1.0.32.7.0.255")
	if err != nil {
		panic(err)
	}
	n, _ := cosem.Number(v)
	fmt.Println(cosem.Scaled(n, s.Exponent), s.Unit)
	// Output: 230.5 V
}
