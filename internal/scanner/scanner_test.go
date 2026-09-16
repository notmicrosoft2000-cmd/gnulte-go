// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package scanner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestGuessOS(t *testing.T) {
	cases := []struct {
		ttl  int
		want string
	}{
		{0, ""}, {32, "Linux/Unix"}, {64, "Linux/Unix"}, {96, "Windows"},
		{128, "Windows"}, {192, "Network device"}, {255, "Network device"},
	}
	for _, c := range cases {
		if got := guessOS(c.ttl); got != c.want {
			t.Errorf("guessOS(%d) = %q, want %q", c.ttl, got, c.want)
		}
	}
}

func TestFingerprintOSSsmbAndRDP(t *testing.T) {
	// SMB-only host with Windows-leaning TTL stays Windows.
	if got := FingerprintOS(128, []Port{{Port: 445}}, "Broadcom", ""); got != "Windows" {
		t.Errorf("SMB fingerprint = %q, want Windows", got)
	}
	// RDP alone is Windows even on a Unix TTL.
	if got := FingerprintOS(64, []Port{{Port: 3389}}, "Intel", ""); got != "Windows" {
		t.Errorf("RDP fingerprint = %q, want Windows", got)
	}
	// SMB on a known NAS vendor must not report Windows.
	if got := FingerprintOS(64, []Port{{Port: 445}}, "Synology Inc.", "NAS"); got != "NAS firmware" {
		t.Errorf("NAS SMB fingerprint = %q, want NAS firmware", got)
	}
}

func TestFingerprintOSBannerSignals(t *testing.T) {
	cases := []struct {
		name   string
		ttl    int
		ports  []Port
		vendor string
		typ    string
		want   string
	}{
		{"ssh openssh", 64, []Port{{Port: 22, Service: "ssh", Banner: "SSH-2.0-OpenSSH_9.6"}, {Port: 80, Banner: "nginx/1.24"}}, "Raspberry Pi Foundation", "Computer", "Linux (Raspberry Pi)"},
		{"ssh openssh synology", 128, []Port{{Port: 22, Banner: "SSH-2.0-OpenSSH_8.2"}}, "Synology Inc.", "NAS", "Synology DSM"},
		{"apple ssh", 64, []Port{{Port: 22, Banner: "SSH-2.0-OpenSSH_9.0"}}, "Apple Inc.", "Computer", "macOS"},
		{"microsoft ftp", 128, []Port{{Port: 21, Banner: "Microsoft FTP Service"}}, "Dell Inc.", "Computer", "Windows"},
		{"windows openssh", 128, []Port{{Port: 22, Banner: "SSH-2.0-OpenSSH_for_Windows_8"}}, "Dell Inc.", "Computer", "Windows"},
		{"iis", 128, []Port{{Port: 80, Banner: "Server: Microsoft-IIS/10.0"}}, "Dell Inc.", "Computer", "Windows Server"},
		{"openwrt", 64, []Port{{Port: 80, Banner: "nginx/1.18"}, {Port: 22, Banner: "SSH-2.0-dropbear_2020.81"}}, "TP-Link", "Router/Gateway", "Router firmware"},
		{"cisco", 255, []Port{{Port: 443}}, "Cisco Systems", "Router/Gateway", "Router firmware"},
		{"printer canon", 64, []Port{{Port: 80, Banner: "CANON"}}, "Canon Inc.", "Printer", "Printer firmware"},
		{"android vendor", 64, []Port{{Port: 5555}}, "Xiaomi Communications", "Mobile", "Android"},
		{"apple phone", 48, []Port{{}}, "Apple Inc.", "Mobile", "iOS"},
	}
	for _, c := range cases {
		if got := FingerprintOS(c.ttl, c.ports, c.vendor, c.typ); got != c.want {
			t.Errorf("%s: FingerprintOS = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFingerprintOSFallbackBucket(t *testing.T) {
	if got := FingerprintOS(64, nil, "", ""); got != "Linux/Unix" {
		t.Errorf("fallback TTL bucket = %q, want Linux/Unix", got)
	}
	if got := FingerprintOS(128, nil, "Generic", "Device"); got != "Windows" {
		t.Errorf("fallback TTL bucket = %q, want Windows", got)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("220 ftp\r\n220 second"); got != "220 ftp 220 second" {
		t.Errorf("sanitize = %q", got)
	}
	// control bytes (including NUL) must never leak raw into a report.
	if got := sanitize("a\x00b\x1b[31m c"); strings.ContainsRune(got, '\x00') || strings.ContainsRune(got, '\x1b') {
		t.Errorf("sanitize leaked control bytes: %q", got)
	}
	long := strings.Repeat("x", 400)
	if got := sanitize(long); len(got) > 200 {
		t.Errorf("sanitize did not truncate: len=%d", len(got))
	}
}

func TestPortOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	if !portOpen(ctx, "127.0.0.1", port) {
		t.Errorf("open listener port %d reported closed", port)
	}
	ln.Close()
	time.Sleep(50 * time.Millisecond)
	if portOpen(ctx, "127.0.0.1", port) {
		t.Errorf("closed port %d reported open", port)
	}
}

func TestBannerFor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("220 GNULTE test FTP server ready\r\n"))
	}()
	got := bannerFor(context.Background(), "127.0.0.1", port)
	if !strings.Contains(got, "GNULTE test FTP") {
		t.Errorf("bannerFor = %q, want greeting with server name", got)
	}
}

func TestSortPorts(t *testing.T) {
	in := []Port{{Port: 443}, {Port: 22}, {Port: 80}}
	out := sortPorts(in)
	if out[0].Port != 22 || out[1].Port != 80 || out[2].Port != 443 {
		t.Errorf("sortPorts = %+v, want 22,80,443", out)
	}
}

func TestServiceTableCoversScanPorts(t *testing.T) {
	for _, p := range scanPorts {
		if services[p] == "" {
			t.Errorf("scanPorts %d has no service name", p)
		}
	}
}
