# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, by the author of the
dlms module and from the same standards as its client. No code was
ported or copied from another implementation; the repository's history
records no porting from Gurux, OpenMUC jDLMS, dlms-cosem or any other
DLMS stack, and a search of this module for their names, identifiers and
porting markers finds none. APDUs are encoded and decoded with
gitlab.com/circutor-library/gosem (MIT) as a dependency.

The meter simulator (`sim`) and the IEC 62056-21 meter
(`iec6205621sim`) were first written next to SigmaM2M's DLMS/COSEM and
IEC 62056-21 adapters, to test them without meters, and were part of the
dlms module from its split (2026-10-06). On 2026-10-11 they moved into
this separate module with their commands and the tests that drive the
dlms client against them (`cosemtest`, `lpwantest`, the session tests of
`iec6205621sim`), so that dlms does not depend on its simulator. The
tests that need dlms's unexported code stayed in dlms; a few tests here
were changed to reach the same cases through dlms's exported settings
(`cosem.ThirdParty` instead of the unexported layer fields).

## Standards followed

None is kept in the repository or redistributed. No specification text
is reproduced; comments cite clause, table and figure numbers in our own
words.

| Package | Followed |
|---|---|
| `sim` | The meter side of IEC 62056-5-3:2023 (associations, the HLS mechanisms, security suites 0 to 2, service-specific and general ciphering, general signing, third-party layers, compression, block transfer and general block transfer, selective access, pushes, image transfer), IEC 62056-6-2:2023 (the interface classes it serves, the security setup class 64), IEC 62056-46 and ISO/IEC 13239 (HDLC station), IEC 62056-42 (the modem and identification service), IEC 62056-4-7 (wrapper over TCP and UDP), IEC 62056-5-3 annex C (the data concentrator), EN 13757-1:2021 (DLMS inside M-Bus), RFC 8724 and RFC 9011 (SCHC over LoRaWAN), and the IS 15959 Parts 1 to 3 profiles through dlms's `is15959` catalogue |
| `iec6205621sim` | IEC 62056-21 Edition 1.0 (2002-05): clause 6, annexes A to E, as the package comment lists |

It is a test peer, not a conformance reference: it was written by the
same author from the same documents as the client, so tests against it
show that the two agree, not that either matches a real meter. See the
README for the checks against an independent implementation.

`sim/library.go` (v0.2.0) only copies the meter's state into dlms's
`server` package; the protocol behaviour there is the dlms module's.

## Test values

All keys, secrets, system titles, serial numbers and readings are test
values (see NOTICE). ECDSA keys are generated at run time. The tests
carry `// Covers: SIG-...` comments: requirement IDs of the SigmaM2M
project's compliance report, which mean nothing else here, and some
comments name SigmaM2M specification findings (`F-nnnn`), explained in
the dlms module's PROVENANCE.md.
