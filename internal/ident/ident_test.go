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

func TestDeviceTypeNewHints(t *testing.T) {
	for _, tc := range []struct {
		label, vendor, host string
		want                string
	}{
		{"hikvision cam vendor", "Hangzhou Hikvision Digital Technology Co. Ltd.", "", "Camera/NVR"},
		{"sonos tv/vendor", "Sonos Inc.", "", "Media/TV"},
		{"amazon echo", "Amazon Technologies Inc.", "", "Media/TV"},
		{"tuya iot vendor", "Shenzhen JEMIOT Digital Technology Co.,Ltd", "", "IoT (smart home)"},
		{"esp wifi vendor", "Espressif Inc.", "", "IoT (smart home)"},
		{"canon printer host", "Canon Inc.", "office-printer", "Printer"},
		{"dahua cam", "Zhejiang Dahua Technology", "", "Camera/NVR"},
		{"negreal mobile", "ALIBABA.COM LTD", "", "Device"},
		{"camera hostname", "Acme Corp", "cam-front", "Camera/NVR"},
		{"smartplug hostname", "Acme Corp", "smartplug-01", "IoT (smart home)"},
	} {
		if got := DeviceType(tc.vendor, tc.host, "", nil); got != tc.want {
			t.Errorf("%s: DeviceType(%q,%q) = %q, want %q", tc.label, tc.vendor, tc.host, got, tc.want)
		}
	}
}

func TestARPAReverse(t *testing.T) {
	for _, tc := range []struct {
		owner, want string
		ok          bool
	}{
		{"132.99.168.192.in-addr.arpa", "192.168.99.132", true},
		{"132.99.168.192.in-addr.arpa.", "192.168.99.132", true},
		{"foo.local", "", false},
		{"7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "", false},
		{"x.y.1.2.in-addr.arpa", "", false},
	} {
		got, ok := arpaToIP(tc.owner)
		if ok != tc.ok || got != tc.want {
			t.Errorf("arpaToIP(%q) = %q,%v want %q,%v", tc.owner, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMDNSRRsParse(t *testing.T) {
	qname := encodeName("132.99.168.192.in-addr.arpa")
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 2)
	pkt := append(hdr, qname...)
	pkt = append(pkt, 0, 1, 0, 1)
	// A record: 192.168.99.10 = fedora.local
	pkt = append(pkt, 0xC0, 12)
	pkt = append(pkt, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 168, 99, 10)
	// PTR record: reverse name -> fedora.local
	target := encodeName("fedora.local.")
	pkt = append(pkt, 0xC0, 12)
	pkt = append(pkt, 0, 12, 0, 1, 0, 0, 0, 120, 0, byte(len(target)))
	pkt = append(pkt, target...)

	rrs := mdnsRRs(pkt)
	if len(rrs) != 2 {
		t.Fatalf("mdnsRRs len = %d, want 2", len(rrs))
	}
	if !(rrs[0].typ == 1 && rrs[0].ip.String() == "192.168.99.10") {
		t.Errorf("A record parse wrong: %+v", rrs[0])
	}
	if !(rrs[1].typ == 12 && rrs[1].owner == "132.99.168.192.in-addr.arpa" && rrs[1].target == "fedora.local") {
		t.Errorf("PTR record parse wrong: %+v", rrs[1])
	}
	// The A record's owner follows the packet's answer section, i.e. the
	// question's reverse name; the browse path maps it via arpaToIP.
	if ip, ok := arpaToIP(rrs[1].owner); !ok || ip != "192.168.99.132" {
		t.Errorf("arpaToIP(%q) = %q,%v want 192.168.99.132,true", rrs[1].owner, ip, ok)
	}
}

func TestNBSTATParse(t *testing.T) {
	// Build a realistic NBSTAT reply body: 2 names, then 4 bytes adapter status.
	sixteen := "FRONTIIR-PC" + "     " // 11 chars + 5 spaces = 16
	rdata := []byte{2}
	rdata = append(rdata, []byte(sixteen)...)
	rdata = append(rdata, 0x00, 0x20) // type <20> file server
	rdata = append(rdata, 0x04, 0x00) // flags
	rdata = append(rdata, []byte(sixteen)...)
	rdata = append(rdata, 0x00, 0x00) // type <00> workstation
	rdata = append(rdata, 0x04, 0x00)
	rdata = append(rdata, []byte("\x00\x00\x00\x00")...) // adapter status

	names := parseNBSTAT(rdata)
	if len(names) != 1 || names[0] != "FRONTIIR-PC" {
		t.Errorf("parseNBSTAT = %q, want single [FRONTIIR-PC]", names)
	}

	// Wildcard/error names must be skipped.
	bad := []byte{1}
	bad = append(bad, []byte("*               ")...)
	bad = append(bad, 0x00, 0xC0)
	if names := parseNBSTAT(bad); len(names) != 0 {
		t.Errorf("parseNBSTAT(bad) = %q, want empty", names)
	}
}

func TestNBSTATQueryShape(t *testing.T) {
	q := nbstatQuery()
	if len(q) != 12+1+32+4 {
		t.Fatalf("nbstatQuery length = %d, want %d", len(q), 12+1+32+4)
	}
	if q[12] != 0x20 || q[13] != '*'>>4+0x41 || q[14] != '*'&0x0F+0x41 {
		t.Errorf("nbstatQuery name encoding wrong at start: % x", q[12:16])
	}
	if binary.BigEndian.Uint16(q[len(q)-4:len(q)-2]) != 0x0021 {
		t.Errorf("nbstatQuery qtype != NBSTAT: % x", q[len(q)-4:])
	}
}
