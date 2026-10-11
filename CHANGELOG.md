# Changelog

## v0.2.0 (2026-10-11)

Added

- `Meter.Server`: the meter's objects, profiles, associations and IS
  15959 access rights on dlms v0.2.0's `server` package; tested for
  every IS 15959 profile and association, rights included.
- `dlmssim -engine server`: serves the IS 15959 meter with dlms's
  `server` package.

Changed

- Requires dlms v0.2.0. With a dedicated key, dlms's client now protects
  HLS passes 3 and 4 with the global key; the meter takes both, and the
  general ciphering and third-party tests expect general-glo for pass 3
  and general-ded afterwards.

## v0.1.0 (2026-10-11)

First release: the DLMS/COSEM meter, the data concentrator, the
IEC 62056-21 meter, the LoRaWAN and NB-IoT links, and the tests of dlms's
client against them.
