package netutil

import (
	"testing"
)

func TestHexToIPLittleEndian(t *testing.T) {
	cases := map[string]string{
		"0102AA7F": "127.170.2.1",
		"000099C0": "192.153.0.0",
		"0100007F": "127.0.0.1",
		"04030201": "1.2.3.4",
	}
	for in, want := range cases {
		if ip := hexToIP(in); ip == nil || ip.String() != want {
			t.Errorf("hexToIP(%q) = %v, want %s", in, ip, want)
		}
	}
	if hexToIP("xyz") != nil {
		t.Error("hexToIP should reject malformed input")
	}
}

func TestHostsInCIDR(t *testing.T) {
	got, err := HostsInCIDR("192.168.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("addr[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := HostsInCIDR("not-a-cidr"); err == nil {
		t.Error("expected error for invalid CIDR")
	}
	if _, err := HostsInCIDR("fe80::1/64"); err == nil {
		t.Error("expected IPv6 to be rejected")
	}
}

// TestHostsInCIDRRejectsTooLarge: an unbounded expansion used to size a slice
// for and iterate 2^hostBits addresses, so a /0 could hang or exhaust memory.
// Anything wider than /16 must be refused outright.
func TestHostsInCIDRRejectsTooLarge(t *testing.T) {
	// /15 is over the cap but expands to only 128k addresses without the
	// guard, so checking it first fails a reverted cap promptly rather than
	// hanging on /0.
	for _, cidr := range []string{"10.0.0.0/15", "0.0.0.0/0"} {
		if _, err := HostsInCIDR(cidr); err == nil {
			t.Errorf("HostsInCIDR(%q) should be rejected as too large", cidr)
		}
	}
	got, err := HostsInCIDR("10.0.0.0/16")
	if err != nil {
		t.Fatalf("/16 is the largest allowed and must expand: %v", err)
	}
	if len(got) != 65536 {
		t.Errorf("len = %d, want 65536", len(got))
	}
}

// TestWithInterfaceRecomputes: overriding -i must re-derive self IP/netmask/
// gateway from the chosen interface, not keep the default-route device's values
// (which made the scan derive the wrong subnet).
func TestWithInterfaceRecomputes(t *testing.T) {
	if _, err := ForInterface("lo"); err != nil {
		t.Skipf("loopback IPv4 not available: %v", err)
	}
	base := Config{Interface: "not-lo", SelfIP: "10.9.9.5", Netmask: "255.255.255.0", Gateway: "10.0.0.1"}
	got := WithInterface(base, "lo")
	if got.Interface != "lo" {
		t.Fatalf("interface = %q, want lo", got.Interface)
	}
	if got.SelfIP != "127.0.0.1" {
		t.Errorf("self ip = %q, want 127.0.0.1 (re-derived from lo)", got.SelfIP)
	}
	if got.Gateway == "10.0.0.1" {
		t.Errorf("gateway = %q, want it re-derived or cleared for a different interface", got.Gateway)
	}
}

func TestWithInterfaceNoop(t *testing.T) {
	base := Config{Interface: "eth9", SelfIP: "1.2.3.4", Netmask: "255.255.255.0"}
	if got := WithInterface(base, ""); got != base {
		t.Errorf("an empty override changed the config: %+v", got)
	}
	if got := WithInterface(base, "eth9"); got != base {
		t.Errorf("a same-interface override changed the config: %+v", got)
	}
}

func TestDefaultRouteParses(t *testing.T) {
	cfg, err := DefaultRoute()
	if err != nil {
		t.Skipf("no network in this environment: %v", err)
	}
	if cfg.Interface == "" || cfg.Gateway == "" || cfg.SelfIP == "" {
		t.Errorf("incomplete config: %+v", cfg)
	}
}
