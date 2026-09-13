// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package airframes

import (
	"math/rand"
	"os"
	"os/exec"
	"strings"
)

// MonitorMode inspects a wireless interface and reports whether it is in
// monitor mode. It trusts `iw` when present, then falls back to the kernel's
// ARPHRD type in sysfs (803 = radiotap, 801 = 802.11, both used by monitor
// adapters; 1 = ethernet/managed). An empty return means "cannot determine".
func MonitorMode(iface string) string {
	if out, err := exec.Command("iw", "dev", iface, "info").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "type" {
				if f[1] == "monitor" {
					return "monitor"
				}
				return "not-monitor"
			}
		}
	}
	b, err := os.ReadFile("/sys/class/net/" + iface + "/type")
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(string(b)) {
	case "803", "801":
		return "monitor"
	case "1":
		return "not-monitor"
	}
	return ""
}

// FakeBSSID returns a locally-administered, unicast 48-bit address so a flood
// of synthetic APs never collides with real hardware.
func FakeBSSID() MAC {
	var m MAC
	for i := range m.Addr {
		m.Addr[i] = byte(rand.Intn(256))
	}
	m.Addr[0] |= 0x02 // locally administered
	return m
}

// FakeStation returns a random unicast station address (locally administered,
// so it can never be mistaken for a real device).
func FakeStation() MAC {
	var m MAC
	for i := range m.Addr {
		m.Addr[i] = byte(rand.Intn(256))
	}
	m.Addr[0] |= 0x02
	m.Addr[0] &^= 0x01
	return m
}

// ssidPool is a handful of realistic names for beacon floods.
var ssidPool = []string{
	"GNULTE-TEST", "TESTNET-5G", "home-network", "Netgear54",
	"TP-Link_2026", "AndroidAP", "iPhone", "Linksys-0815",
	"Starbucks", "attwifi", "xfinitywifi", "Peplink",
}

// FakeSSID draws a synthetic network name.
func FakeSSID() string {
	return ssidPool[rand.Intn(len(ssidPool))]
}

// FakeChannel draws a plausible 2.4 or 5 GHz channel.
func FakeChannel() uint8 {
	if rand.Intn(2) == 0 {
		return uint8(1 + rand.Intn(11))
	}
	return uint8(36 + rand.Intn(4)*4)
}
