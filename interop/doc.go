// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop holds tests only: the Gurux DLMS/COSEM library for
// Python, an implementation written independently of ours, reads the
// simulated IS 15959 meter of github.com/cB-Sigma/dlms-sim over the
// IEC 62056-4-7 wrapper and over HDLC on TCP.
//
// The meter runs in the test process; the client runs in a pinned Python
// image, which installs the pinned gurux-dlms package from PyPI and runs
// testdata/gurux_client.py, our own script driving Gurux's client
// classes. No Gurux code is kept in this repository. The tests run only
// when SIGMA_DLMS_INTEROP=1 and docker is on PATH, and need network
// access for the package:
//
//	cd libs/dlms-sim/interop && SIGMA_DLMS_INTEROP=1 GOWORK=off go test -v -timeout 20m ./...
//
// The container reaches the meter at host.docker.internal. On macOS
// (Docker Desktop) the meter listens on 127.0.0.1; elsewhere it listens on
// all interfaces for the duration of a test, since a Linux container
// reaches the host through the bridge.
package interop
