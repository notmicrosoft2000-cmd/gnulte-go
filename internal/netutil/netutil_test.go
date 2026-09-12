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

func TestDefaultRouteParses(t *testing.T) {
	cfg, err := DefaultRoute()
	if err != nil {
		t.Skipf("no network in this environment: %v", err)
	}
	if cfg.Interface == "" || cfg.Gateway == "" || cfg.SelfIP == "" {
		t.Errorf("incomplete config: %+v", cfg)
	}
}
