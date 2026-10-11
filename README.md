# dlms-sim

Simulated DLMS/COSEM smart meters, a data concentrator and an IEC 62056-21 meter in Go, for testing head-end systems and DLMS clients without hardware.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/dlms-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/dlms-sim) [![test](https://github.com/cB-Sigma/dlms-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/dlms-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)

The meter answers associations with no, low or high-level security
(mechanisms 2 to 7, security suites 0 to 2, every ciphering form,
general signing, third-party layers, V.44 compression), GET with block
transfer and selective access, SET and ACTION, sends pushes, and serves
the objects of an IS 15959 (Indian smart meter) profile with plausible,
changing readings. It is reached over the wrapper on TCP or UDP, HDLC
over TCP as through a serial converter (with a modem and the
identification service), a serial port with an IEC 62056-21 optical
head, a data concentrator, an NB-IoT style wake-up link, a LoRaWAN radio
with SCHC, inside M-Bus, or any transport of your own. It is built on
[dlms](https://github.com/cB-Sigma/dlms) and gosem's APDU encoders,
without cgo. Written for SigmaM2M, a oneM2M platform; it has no
dependency on it.

## What is simulated

| Package | What it does |
|---|---|
| `sim` | `Meter`: a DLMS/COSEM meter. Wrapper over TCP (`Listen`) and UDP (`ListenUDP`), HDLC over TCP (`ListenHDLC`, with a modem and the identification service), a serial port with an IEC 62056-21 opening; `NewSession` and `HandleAPDU` for a transport of your own; associations with no, low and high-level security (`HLS`: mechanisms 2 to 7, suites 0 to 2, service-specific and general ciphering with every key-info, general signing, third-party layers, compression, dedicated keys, the broadcast key, the one application context a meter accepts), GET with block transfer and range or entry selective access on profiles, SET, ACTION, general block transfer, pushes, image transfer, the security setup object (class 64); `NewIS15959` builds a meter from an IS 15959 Part 1, 2 or 3 profile with plausible readings; `DCU` (a data concentrator in gateway and logical-device mode); `LoRaWANMeter` (a class A or C radio with SCHC on dlms's in-memory network server); NB-IoT style wake-ups; pre-established associations and DLMS APDUs inside M-Bus |
| `iec6205621sim` | `Meter`: an IEC 62056-21 meter on TCP as through a transparent converter with 7E1 emulated: modes A to E, programming mode (R1 to R6, W1 to W5, E2, partial blocks), annex C formatted codes, the annex B wake-ups, mode D pushes, and the mode E switch to the DLMS meter over HDLC |
| `cmd/dlmssim` | Serves an IS 15959 meter on TCP, UDP or HDLC |
| `cmd/iec6205621sim` | Serves an IEC 62056-21 meter |
| `cosemtest`, `lpwantest` | No code: the tests of dlms's client and LoRaWAN bridge against these simulators |

Not simulated: short name referencing, the IEC 62056-8-20 mesh, real
radio timing, and meter firmware quirks other than the ones the package
comments name (for example a meter that hangs up after an ACTION, or
answers UDP from another port).

## Install

```
go get github.com/cB-Sigma/dlms-sim@latest
```

Requires Go 1.25 or later. The commands:

```
go install github.com/cB-Sigma/dlms-sim/cmd/dlmssim@latest
go install github.com/cB-Sigma/dlms-sim/cmd/iec6205621sim@latest
```

## Command line

```
dlmssim -profile part2-1ph -listen 127.0.0.1:4059 -hdlc 127.0.0.1:4060
dlmssim -profile part3-ctpt -udp 127.0.0.1:4059 -rows 96
iec6205621sim -baud 5 -password 00000000
```

`dlmssim` prints the associations, the meter reader password and the
global keys (test values), then serves until interrupted.

| Flag | Default | Meaning |
|---|---|---|
| `-profile` | `part2-1ph` | IS 15959 profile (`dlmssim -h` lists them) |
| `-serial` | `00000001` | meter serial number |
| `-password` | `ABCDEFGH` | the meter reader's (client 32) low-level secret |
| `-listen` | `127.0.0.1:4059` | TCP address of the wrapper (empty: none) |
| `-udp` | | UDP address of the wrapper (empty: none) |
| `-hdlc` | | TCP address of HDLC, as through a serial converter (empty: none) |
| `-rows` | `48` | entries in each profile and event log |

`iec6205621sim` takes `-baud` (0 to 6: mode C; A to F: mode B; M: mode
A), `-password` (programming mode P1), `-address` (the device address it
answers), `-manufacturer` and `-model`; it listens on a free port of
127.0.0.1 and prints the address.

## In Go tests

A meter of your own objects, read by dlms's client with HLS-GMAC and a
dedicated key (from `Example_cosemClient`):

```go
meter := &sim.Meter{HLS: &sim.HLS{Policy: 0x30, SystemTitle: []byte("SIM\x00\x00\x00\x00\x01"),
	Key: key, AuthKey: ak, FrameCounterOBIS: "0.0.43.1.3.255"}}
meter.Register("1.0.32.7.0.255", axdr.CreateAxdrLongUnsigned(23050), -2, 35) // 230.50 V
meter.Set(1, "0.0.43.1.3.255", 2, axdr.CreateAxdrDoubleLongUnsigned(41))
addr, err := meter.Listen("127.0.0.1:0")
defer meter.Close()
// dial addr with cosem.NewClient and wrapper.New("tcp", addr, ...)
```

An IS 15959 meter behind a transport of your own (from
`ExampleMeter_HandleAPDU`):

```go
sp, _ := is15959.Get("part2-1ph")
m := sim.NewIS15959(sp, sim.IS15959Options{Serial: "00001401"})
m.Prepare()
s := m.NewSession(16)        // the public client
aare := m.HandleAPDU(s, aarq) // APDUs in, APDUs out
```

The meter counts what it saw (`Associations`, `Forms`, `Signed`,
`Compressed`, `Sets`, `Actions`, `StaleCounters` and more), so a test
can check what a client actually sent.

## Demo values

Every key, secret, system title, serial number and reading is a test
value (NOTICE lists the defaults). Do not use them on real meters.

## Documentation

Reference: https://pkg.go.dev/github.com/cB-Sigma/dlms-sim

## Testing

```
go vet ./...
go test -race ./...
```

`cosemtest` runs dlms's client against the meter in every security
combination, `lpwantest` runs its LoRaWAN bridge, and `iec6205621sim`'s
tests run dlms's IEC 62056-21 sessions. The simulators were written by
the author of dlms from the same standards, so these tests show that the
two agree, not that either matches a real meter.

### Interop tested against

Against Gurux, written independently of this module, on 2026-10-11
(`interop/`, a nested test-only module; the meter runs in the test and
the client in Docker; `cd interop && SIGMA_DLMS_INTEROP=1 go test -v ./...`).
Peer: Gurux's DLMS client for Python, `gurux-dlms==1.0.203` from PyPI in
`python:3.12.10-slim`, driven by our own script (`testdata/gurux_client.py`).

| Check (Gurux client against the simulated IS 15959 meter) | Wrapper | HDLC |
|---|---|---|
| No security, public client (16), Part 1 meter | pass | pass |
| Low-level security, meter reader (32): clock, register with scaler and unit, data object, the block load profile whole (in blocks), by entry and by range | pass | pass |
| HLS mechanism 2, utility settings client (48) | pass | pass |
| Low-level security with APDUs encrypted under the global key (Part 2 meter, suite 0) | pass | pass |
| HLS-GMAC, suite 0, authenticated and encrypted APDUs: clock, register, the block load profile in blocks | pass | pass |
| A wrong low-level password is refused | pass | |

The [dlms](https://github.com/cB-Sigma/dlms) client against Gurux's
server is recorded in that module. Not yet: a real head-end system or
another client than Gurux, and the simulator's suites 1 and 2, general
ciphering and signing against another implementation.

## Related repositories

- [dlms](https://github.com/cB-Sigma/dlms): the DLMS/COSEM client, its
  lower layers, IEC 62056-21, OBIS and the IS 15959 catalogue.
- [mbus-sim](https://github.com/cB-Sigma/mbus-sim): simulated wired and
  wireless M-Bus meters.

## Status

v0.x. The API may change before v1. Tests carry `// Covers: SIG-...`
comments: requirement IDs of the SigmaM2M project's compliance report,
which mean nothing else here.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE)). Copyright 2026 Abhinav Gautam.
[NOTICE](NOTICE) lists the dependencies and names the trademarks used.
