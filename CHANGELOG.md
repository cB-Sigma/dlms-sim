# Changelog

## v0.3.0 (2026-10-11)

Requires dlms v0.3.0. Backwards compatible with v0.2.0.

Changed

- The simulators now run on the library's packages: `DCU` on dlms's
  `concentrator` (each meter's session runs on its own, so a slow meter
  no longer holds up the others on one head-end connection);
  `iec6205621sim.Meter` and `Line` are aliases of dlms's
  `iec6205621/meter`; `NewIS15959` takes its objects, values,
  associations and keys from dlms's `is15959/meter` (`IS15959Options` and
  `Keys` are aliases of its `Options` and `Keys`, which add `Location`
  and nameplate fields); `Recapture` and the profile values come from the
  same package; `LoRaWANMeter` and `NBIoTMeter` run on dlms's
  `lpwan/enddevice`.
- The IS 15959 meter's instantaneous registers read like a household
  load on a 230 V, 50 Hz supply (they were small counters, a voltage
  register read 1.82 V; found by Gurux's client).
- Requests over LoRaWAN to the all-station address are served and not
  answered, as over the wrapper.

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
