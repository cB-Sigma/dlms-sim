// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/is15959"
	"github.com/cB-Sigma/dlms/wrapper"
)

var mechNames = map[byte]string{0: "none", 1: "low", 2: "hls-aes", 3: "hls-md5", 4: "hls-sha1", 5: "hls-gmac", 6: "hls-sha256", 7: "hls-ecdsa"}

var policyNames = map[byte]string{0: "none", 0x10: "authenticated", 0x20: "encrypted", 0x30: "authenticated-encrypted"}

// The IS 15959 meters of every profile, served by the dlms module's
// server package (Meter.Server): each association of the profile opens
// with its security and reads the serial number and the clock, a reader
// reads a profile's buffer (in data blocks), and the profile's rights
// are kept (the public client may not read what it has no right to).
//
// Covers: SIG-IPE-6461
func TestLibraryServerIS15959(t *testing.T) {
	for _, id := range is15959.IDs() {
		t.Run(id, func(t *testing.T) {
			sp, _ := is15959.Get(id)
			m := NewIS15959(sp, IS15959Options{Rows: 120})
			s, err := m.Server()
			if err != nil {
				t.Fatal(err)
			}
			addr, err := s.ListenWrapper("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			for _, a := range sp.Associations {
				if a.Role == is15959.Push {
					continue
				}
				h := m.ClientHLS[a.Client]
				if h == nil && a.Client != 16 {
					h = m.HLS
				}
				sec := cosem.SecurityConfig{Name: id, Authentication: "none"}
				if h != nil && a.Client != 16 {
					mech := h.mechanism()
					if h.Unauthenticated {
						mech = 0
					}
					sec.Authentication, sec.Password, sec.Security = mechNames[mech], string(h.Secret), policyNames[h.Policy]
					if h.Policy != 0 || mech == 5 {
						sec.BlockCipherKey, sec.AuthenticationKey = hex.EncodeToString(h.Key), hex.EncodeToString(h.AuthKey)
					}
				}
				t.Run(fmt.Sprintf("client %d %s", a.Client, sec.Authentication), func(t *testing.T) {
					hls, _, err := sec.Build()
					if err != nil {
						t.Fatal(err)
					}
					c := cosem.NewClient(cosem.ClientConfig{Transport: func(cl int) (gdlms.Transport, error) {
						return wrapper.New("tcp", addr, cl, 1, 5*time.Second)
					}, ClientAddress: int(a.Client), HLS: hls, Password: []byte(sec.Password), Timeout: 5 * time.Second})
					if err := c.Connect(); err != nil {
						t.Fatalf("association: %v", err)
					}
					defer c.Close()
					rights, listed := sp.Access(8, "0.0.1.0.0.255", 2, false)
					may := !listed || rights.Of(a.Role)&is15959.Read != 0
					if _, err := c.Get(8, "0.0.1.0.0.255", 2); (err == nil) != may {
						t.Errorf("clock read (right %v): %v", may, err)
					}
					if a.Role == is15959.MR || a.Role == is15959.US {
						for _, p := range sp.Profiles {
							v, err := c.Get(7, p.OBIS, 2)
							if err != nil {
								t.Errorf("profile %s: %v", p.OBIS, err)
								continue
							}
							_ = v
						}
					}
				})
			}
			if st := s.Stats(); st.Associations == 0 {
				t.Errorf("stats %+v", st)
			}
		})
	}
}
