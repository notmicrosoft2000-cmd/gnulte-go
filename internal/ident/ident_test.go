package ident

import (
	"encoding/binary"
	"testing"
)

func TestVendorFromEmbedded(t *testing.T) {
	for _, tc := range []struct {
		mac, want string
	}{
		{"B8:27:EB:12:34:56", "Raspberry Pi Foundation"},
		{"B827EB123456", "Raspberry Pi Foundation"},
		{"b8-27-eb-00-00-01", "Raspberry Pi Foundation"},
		{"AC:BC:32:00:00:01", "Apple, Inc."},
		{"00:50:56:00:00:01", "VMware, Inc."},
		{"", ""},
		{"ZZ:ZZ:ZZ:12:34:56", ""}, // garbage, no match
	} {
		got := Vendor(tc.mac)
		if got != tc.want {
			t.Errorf("Vendor(%q) = %q, want %q", tc.mac, got, tc.want)
		}
	}
}

func TestParseOUIFormats(t *testing.T) {
	db := map[string]string{}
	parseOUI("B8-27-EB\tRaspberry Pi\n00-00-2E   (hex)\t\tCISCO SYSTEMS\n# comment\n", db)
	if db["B827EB"] != "Raspberry Pi" {
		t.Errorf("tabbed entry not parsed: %+v", db)
	}
	if db["00002E"] != "CISCO SYSTEMS" {
		t.Errorf("IEEE (hex) entry not parsed: %+v", db)
	}
}

func TestMDNSPTR(t *testing.T) {
	// Build a response: header qd=1 an=2, a question for the reverse name, an
	// A-record for an unrelated device and the PTR we want, compressed so the
	// name parsing is exercised.
	qname := encodeName("132.99.168.192.in-addr.arpa")
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 2)
	pkt := append(hdr, qname...)
	pkt = append(pkt, 0, 1, 0, 1) // qtype A, qclass IN
	// RR1: A record for 192.168.99.10, name = pointer to qname offset
	pkt = append(pkt, 0xC0, 12) // name -> offset 12 (the question's name)
	pkt = append(pkt, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 168, 99, 10)
	// RR2: PTR for our name pointing to "office-printer.local."
	target := encodeName("office-printer.local.")
	// store target after RR1 for compression
	pkt = append(pkt, 0xC0, 12)
	pkt = append(pkt, 0, 12, 0, 1, 0, 0, 0, 120, 0, byte(len(target)))
	pkt = append(pkt, target...)

	name, ok := mdnsPTR(pkt)
	if !ok {
		t.Fatalf("mdnsPTR found no PTR")
	}
	if name != "office-printer.local." {
		t.Errorf("mdnsPTR = %q, want %q", name, "office-printer.local.")
	}
}

func encodeName(name string) []byte {
	var out []byte
	for _, l := range splitName(name) {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	return out
}

func splitName(name string) []string {
	out := []string{}
	for _, p := range splitComma(name) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitComma(name string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return out
}

func TestDeviceType(t *testing.T) {
	for _, tc := range []struct {
		label, vendor, host, ports string
		banners                    []string
		want                       string
	}{
		{"apple vendor", "Apple, Inc.", "foo", "", nil, "Apple device"},
		{"iphone host", "Acme", "bobs-iphone", "", nil, "Apple device"},
		{"android host", "", "my-android", "", nil, "Mobile"},
		{"tplink vendor", "TP-Link Technologies Co.,Ltd.", "", "", nil, "Router/AP"},
		{"raspi vendor", "Raspberry Pi Foundation", "", "", nil, "Raspberry Pi"},
		{"windows host", "Intel Corporate", "CORP-PC", "", nil, "Computer"},
		{"roku port", "", "", "8060/open/tcp, 80/open/tcp/http", nil, "Roku"},
		{"printer port", "Canon Inc.", "", "515/open/tcp, 9100/open/tcp", nil, "Printer"},
		{"iphone sync port", "", "", "62078/open/tcp", nil, "Apple device (iPhone/iPad)"},
		{"cast banner", "", "", "8009/open/tcp", []string{"80: Google Cast"}, "Google Cast"},
		{"unknown", "", "", "", nil, ""},
		{"unknown with ports", "", "", "22/open/tcp/ssh", nil, "Device"},
	} {
		if got := DeviceType(tc.vendor, tc.host, tc.ports, tc.banners); got != tc.want {
			t.Errorf("%s: DeviceType(%q,%q,%q,%v) = %q, want %q",
				tc.label, tc.vendor, tc.host, tc.ports, tc.banners, got, tc.want)
		}
	}
}
