//go:build cgo
// +build cgo

package openssl

import "testing"

func TestFIPSModeSet(t *testing.T) {
	wasEnabled := FIPSMode()
	defer func() {
		if err := FIPSModeSet(wasEnabled); err != nil {
			t.Fatalf("failed to restore FIPS mode: %v", err)
		}
	}()

	if err := FIPSModeSet(true); err != nil {
		t.Skipf("OpenSSL FIPS provider is not available: %v", err)
	}
	if !FIPSMode() {
		t.Fatal("FIPS mode should be enabled")
	}

	if err := FIPSModeSet(false); err != nil {
		t.Fatalf("failed to disable FIPS mode: %v", err)
	}
	if FIPSMode() {
		t.Fatal("FIPS mode should be disabled")
	}
}
