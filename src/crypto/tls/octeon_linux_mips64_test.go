// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package tls

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140deps/cpu"
	"testing"
)

// Capture the production value before runMain disables hardware preference
// for the rest of the TLS test suite.
var octeonInitialAESGCMHardwareSupport = hasAESGCMHardwareSupport

func TestOcteonGCMTLS(t *testing.T) {
	testOcteonGCMTLS(t, false)
}

// Keep the negotiated cipher identical in both modes, so a debugger can
// distinguish COP2 AES-GCM from the software AES-GCM record path.
func TestOcteonGCMTLSForcedAES(t *testing.T) {
	testOcteonGCMTLS(t, true)
}

func testOcteonGCMTLS(t *testing.T, forceAES bool) {
	t.Helper()
	previous := hasAESGCMHardwareSupport
	t.Cleanup(func() { hasAESGCMHardwareSupport = previous })
	hasAESGCMHardwareSupport = octeonInitialAESGCMHardwareSupport

	wantHardware := cpu.OcteonCOP2 && !fips140.Enabled && fips140.Version() == "latest"
	if hasAESGCMHardwareSupport != wantHardware {
		t.Fatalf("AES-GCM hardware preference = %v, want %v", hasAESGCMHardwareSupport, wantHardware)
	}
	if forceAES {
		// Config.CipherSuites only controls TLS 1.2 and earlier. Restrict
		// both TLS 1.3 preference lists for this nonparallel test only.
		aes, noAES := defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES
		t.Cleanup(func() {
			defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES = aes, noAES
		})
		defaultCipherSuitesTLS13 = []uint16{TLS_AES_128_GCM_SHA256}
		defaultCipherSuitesTLS13NoAES = defaultCipherSuitesTLS13
	}
	for _, tc := range []struct {
		name                 string
		version, aes, chacha uint16
	}{
		{"TLS12", VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
		{"TLS13", VersionTLS13, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConfigClient.Clone(), testConfigServer.Clone()
			client.MinVersion, client.MaxVersion = tc.version, tc.version
			server.MinVersion, server.MaxVersion = tc.version, tc.version
			client.CipherSuites = []uint16{tc.aes, tc.chacha}
			if forceAES {
				client.CipherSuites = []uint16{tc.aes}
			}
			server.CipherSuites = client.CipherSuites
			serverState, clientState, err := testHandshake(t, client, server)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.chacha
			if forceAES || wantHardware || fips140.Enabled {
				want = tc.aes
			}
			if serverState.CipherSuite != want || clientState.CipherSuite != want {
				t.Fatalf("cipher suite (server,client) = (%#04x,%#04x), want %#04x", serverState.CipherSuite, clientState.CipherSuite, want)
			}
		})
	}
}
