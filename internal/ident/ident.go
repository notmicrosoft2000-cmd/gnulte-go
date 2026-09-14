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

// Package ident identifies LAN devices: vendor lookup from a MAC address
// (embedded IEEE registry, overridable by a local file), hostname discovery
// via reverse DNS and multicast-DNS (.local), and a conservative device-type
// guess from vendor, hostname and the open ports a scan found.
package ident

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed oui.txt
var embeddedOUI string

// Vendor maps the 3-byte OUI prefix of a MAC address (upper hex, any
// separator) to the organisation that registered it. The embedded registry
// is the IEEE 24-bit block; optional external files may override it so a
// user's fresher copy always wins.
func Vendor(mac string) string {
	if mac == "" {
		return ""
	}
	hex := strings.ToUpper(strings.Join(strings.FieldsFunc(mac, func(r rune) bool {
		return r == ':' || r == '-'
	}), ""))
	if len(hex) < 6 {
		return ""
	}
	if v, ok := ouiTable()[hex[:6]]; ok {
		return v
	}
	return ""
}

var (
	ouiOnce  sync.Once
	ouiCache map[string]string
)

func ouiTable() map[string]string {
	ouiOnce.Do(func() {
		ouiCache = map[string]string{}
		parseOUI(embeddedOUI, ouiCache)
		for _, p := range externalUI() {
			if raw, err := os.ReadFile(p); err == nil {
				parseOUI(string(raw), ouiCache)
			}
		}
	})
	return ouiCache
}

// externalUI lists registry files checked after the embedded snapshot, in
// increasing precedence. The arp-scan one ships complete on many systems and
// the per-user file lets anyone maintain a corrected copy.
func externalUI() []string {
	home, _ := os.UserHomeDir()
	paths := []string{"/usr/share/arp-scan/ieee-oui.txt"}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "gnulte-go", "oui.txt"))
	}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".config", "gnulte-go", "oui.txt"))
	}
	return append(paths, "/usr/share/gnulte/oui.txt", "/usr/share/gnulte-go/oui.txt")
}

// parseOUI folds registry text into the table. Both the arp-scan format
// ("B8:27:EB\tVendor" / "B827EB\tVendor") and the IEEE plain format
// ("00-00-2E   (hex)  Vendor") are understood; keys are always uppercased
// hex without separators.
func parseOUI(raw string, db map[string]string) {
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hex, vendor := "", ""
		if i := strings.Index(line, "\t"); i >= 0 {
			hex = cleanPrefix(line[:i])
			vendor = strings.TrimSpace(line[i+1:])
			// IEEE official lines put "(hex)" before the tab; the tab branch
			// then fails the 6-hex check and we fall through to the (hex) form.
			if len(hex) != 6 || vendor == "" {
				hex, vendor = "", ""
			}
		}
		if hex == "" {
			if i := strings.Index(line, "  (hex)"); i >= 0 {
				hex = cleanPrefix(line[:i])
				if j := strings.Index(line, ")"); j >= 0 {
					vendor = strings.TrimSpace(line[j+1:])
				}
			}
		}
		if len(hex) != 6 || vendor == "" || vendor == "IEEE Registration Authority" {
			continue
		}
		db[hex] = vendor
	}
}

func cleanPrefix(s string) string {
	r := strings.NewReplacer(":", "", "-", "")
	return strings.ToUpper(r.Replace(strings.TrimSpace(s)))
}

// Hostname identifies a device by name: classic reverse DNS first, then a
// multicast-DNS .local lookup when the LAN has no reverse zone (the common
// case). Both are time-bounded so a quiet network cannot stall a scan.
func Hostname(ctx context.Context, ip string) string {
	dctx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	r, err := net.DefaultResolver.LookupAddr(dctx, ip)
	cancel()
	if err == nil && len(r) > 0 {
		return strings.TrimSuffix(r[0], ".")
	}
	if n, ok := reverseMDNS(ctx, ip); ok {
		return n
	}
	return ""
}

// reverseMDNS resolves ip's .local name by querying the multicast DNS channel
// (RFC 6762) with the PTR for the address's ip.arpa name. The UnicastResponse
// bit asks the owner to reply straight to our socket, so we do not need to
// join the group to hear it.
func reverseMDNS(ctx context.Context, ip string) (string, bool) {
	ip4 := net.ParseIP(ip)
	if ip4 == nil || ip4.To4() == nil {
		return "", false
	}
	o := ip4.To4()
	b := &bytes.Buffer{}
	b.Write([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	writeName(b, strings.Join([]string{
		strconv.Itoa(int(o[3])), strconv.Itoa(int(o[2])),
		strconv.Itoa(int(o[1])), strconv.Itoa(int(o[0])),
		"in-addr", "arpa",
	}, "."))
	b.Write([]byte{0, 12, 0x80, 0x01}) // qtype PTR, qclass IN + UnicastResponse

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
	if err != nil {
		return "", false
	}
	defer conn.Close()
	deadline, has := ctx.Deadline()
	if !has {
		deadline = time.Now().Add(800 * time.Millisecond)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(b.Bytes()); err != nil {
		return "", false
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return "", false
		}
		if name, ok := mdnsPTR(buf[:n]); ok {
			return strings.TrimSuffix(name, "."), true
		}
	}
}

func writeName(b *bytes.Buffer, name string) {
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
}

// mdnsPTR scans a DNS/mDNS response for a PTR record whose target looks like
// a hostname (ends in .local), returning that name.
func mdnsPTR(pkt []byte) (string, bool) {
	if len(pkt) < 12 {
		return "", false
	}
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	pos := 12
	for i := 0; i < qdcount; i++ {
		_, n, ok := skipName(pkt, pos)
		if !ok {
			return "", false
		}
		pos = n + 4
	}
	for i := 0; i < ancount; i++ {
		_, n, ok := skipName(pkt, pos)
		if !ok {
			return "", false
		}
		pos = n
		if pos+10 > len(pkt) {
			return "", false
		}
		rtype := binary.BigEndian.Uint16(pkt[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[pos+8 : pos+10]))
		pos += 10
		if rtype == 12 { // PTR
			if name, nn, ok := skipName(pkt, pos); ok {
				pos = nn
				if strings.HasSuffix(strings.ToLower(name), ".local.") {
					return name, true
				}
				continue
			}
			return "", false
		}
		pos += rdlen
	}
	return "", false
}

// skipName walks a (possibly compressed) DNS name. It returns the fully
// expanded name, the byte offset just past the name as written at the top
// level (after the first pointer, or after the terminating zero), and whether
// parsing succeeded.
func skipName(pkt []byte, start int) (string, int, bool) {
	var labels []string
	pos := start
	consumed := start
	jumps := 0
	for {
		if pos >= len(pkt) {
			return "", 0, false
		}
		l := int(pkt[pos])
		switch {
		case l == 0:
			pos++
			if jumps == 0 {
				consumed = pos
			}
			name := strings.Join(labels, ".")
			if len(labels) > 0 {
				name += "."
			}
			return name, consumed, true
		case l&0xC0 == 0xC0:
			if pos+1 >= len(pkt) {
				return "", 0, false
			}
			if consumed == start {
				consumed = pos + 2
			}
			off := int(binary.BigEndian.Uint16(pkt[pos:pos+2]) & 0x3FFF)
			jumps++
			if jumps > 16 || off >= len(pkt) {
				return "", 0, false
			}
			pos = off
		default:
			if l > 63 || pos+1+l > len(pkt) {
				return "", 0, false
			}
			labels = append(labels, string(pkt[pos+1:pos+1+l]))
			pos += 1 + l
			if jumps == 0 {
				consumed = pos
			}
		}
	}
}

// DeviceType labels a host from what we know about it: a strong vendor or
// hostname hint wins; otherwise open ports and service banners supply a
// conservative guess. It returns "" for a totally unknown device.
func DeviceType(vendor, hostname, ports string, banners []string) string {
	v := strings.ToLower(vendor)
	n := strings.ToLower(hostname)
	pl := strings.ToLower(ports)
	b := strings.ToLower(strings.Join(banners, " "))

	switch {
	case strings.Contains(v, "apple") ||
		strings.Contains(n, "ipad") || strings.Contains(n, "iphone") ||
		strings.Contains(n, "imac") || strings.Contains(n, "macbook"):
		return "Apple device"
	case strings.Contains(v, "samsung") || strings.Contains(v, "xiaomi") ||
		strings.Contains(v, "oneplus") || strings.Contains(v, "motorola") ||
		strings.Contains(v, "huawei") || strings.Contains(n, "android") ||
		strings.Contains(n, "galaxy") || strings.Contains(n, " phone"):
		return "Mobile"
	case strings.Contains(v, "tp-link") || strings.Contains(v, "asus") ||
		strings.Contains(v, "netgear") || strings.Contains(v, "linksys") ||
		strings.Contains(v, "d-link") || strings.Contains(v, "dlink") ||
		strings.Contains(v, "totolink") || strings.Contains(v, "belkin") ||
		strings.Contains(v, "zyxel"):
		return "Router/AP"
	case strings.Contains(n, "router") || strings.Contains(n, "openwrt") ||
		strings.Contains(n, "gateway") || strings.Contains(n, "ap-"):
		return "Router/AP"
	case strings.Contains(v, "raspberry"):
		return "Raspberry Pi"
	case strings.Contains(v, "microsoft") || strings.Contains(v, "intel") ||
		strings.Contains(v, "dell") || strings.Contains(v, "lenovo") ||
		strings.Contains(v, "hewlett") || strings.Contains(n, "windows") ||
		strings.Contains(n, "desktop") || strings.Contains(n, "laptop"):
		return "Computer"
	}

	// A registered but uncategorised vendor still gets to benefit from open
	// ports when the deep scan found some (e.g. a TP-LINK printer).
	if vendor != "" {
		if res := guessByPorts(pl, b); res != "" && res != "Device" {
			return res
		}
		return "Device"
	}
	return guessByPorts(pl, b)
}

// guessByPorts draws device-type hints from well-known open ports a scan
// found, and is deliberately conservative so a wrong guess is unlikely.
func guessByPorts(pl, b string) string {
	// Nothing to guess from: remain "unknown".
	if pl == "" && strings.TrimSpace(b) == "" {
		return ""
	}
	ports := map[int]bool{}
	for _, f := range strings.FieldsFunc(pl, func(r rune) bool {
		return r == ',' || r == ' ' || r == '/' || r == '\t'
	}) {
		if n, err := strconv.Atoi(f); err == nil {
			ports[n] = true
		}
	}
	isOpen := func(p int) bool { return ports[p] }
	if strings.Contains(b, "airplay") || strings.Contains(b, "bonjour") {
		return "Apple device"
	}
	if strings.Contains(b, "google_cast") || strings.Contains(b, "chromecast") {
		return "Google Cast"
	}
	if strings.Contains(b, "roku") {
		return "Roku"
	}
	switch {
	case isOpen(62078):
		return "Apple device (iPhone/iPad)"
	case isOpen(33722) || isOpen(12898):
		return "Mobile (Android MTP)"
	case isOpen(8060):
		return "Roku"
	case isOpen(8009):
		return "Google Cast"
	case isOpen(554) || isOpen(8554):
		return "Media/IoT (camera?)"
	case isOpen(9100) || isOpen(515) || isOpen(631):
		return "Printer"
	case isOpen(445) || isOpen(139) || isOpen(3389):
		return "Computer"
	case (isOpen(443) && isOpen(80)) || isOpen(8080):
		return "Media/IoT"
	}
	return "Device"
}
