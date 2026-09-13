package main

import "testing"

func TestSubnetCIDR(t *testing.T) {
	for _, tc := range []struct {
		ip, mask, want string
	}{
		{"192.168.1.50", "255.255.255.0", "192.168.1.0/24"},
		{"10.1.2.3", "255.255.254.0", "10.1.2.0/23"},
		{"192.168.9.7", "255.255.255.128", "192.168.9.0/25"},
		{"172.16.5.9", "255.255.0.0", "172.16.0.0/16"},
		{"192.168.1.1", "bogus", "192.168.1.1/24"},
	} {
		if got := subnetCIDR(tc.ip, tc.mask); got != tc.want {
			t.Errorf("subnetCIDR(%s, %s) = %s, want %s", tc.ip, tc.mask, got, tc.want)
		}
	}
}
