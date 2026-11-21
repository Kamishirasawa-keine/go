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

func TestOcteonGCMTLS(t *testing.T) {
	wantHardware := cpu.OcteonCOP2 && !fips140.Enabled && fips140.Version() == "latest"
	if hasAESGCMHardwareSupport != wantHardware {
		t.Fatalf("AES-GCM hardware preference = %v, want %v", hasAESGCMHardwareSupport, wantHardware)
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
			server.CipherSuites = client.CipherSuites
			serverState, clientState, err := testHandshake(t, client, server)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.chacha
			if wantHardware || fips140.Enabled {
				want = tc.aes
			}
			if serverState.CipherSuite != want || clientState.CipherSuite != want {
				t.Fatalf("cipher suite (server,client) = (%#04x,%#04x), want %#04x", serverState.CipherSuite, clientState.CipherSuite, want)
			}
		})
	}
}
