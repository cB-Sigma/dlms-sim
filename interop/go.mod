// Test-only module: Gurux's DLMS client against github.com/cB-Sigma/dlms-sim's
// simulated meter, in Docker (see interop_test.go). Not part of the
// published module.
module github.com/cB-Sigma/dlms-sim/interop

go 1.25

replace github.com/cB-Sigma/dlms-sim => ../

require (
	github.com/cB-Sigma/dlms v0.1.0
	github.com/cB-Sigma/dlms-sim v0.0.0
)

require (
	github.com/cB-Sigma/schc v0.1.1 // indirect
	gitlab.com/circutor-library/gosem v1.3.4 // indirect
)
