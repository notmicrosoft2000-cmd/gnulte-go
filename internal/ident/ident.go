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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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
		// System knowledge: fill gaps only, so a truncated nmap name never
		// outranks the full IEEE one we already carry.
		for _, p := range systemUI() {
			if raw, err := os.ReadFile(p); err == nil {
				patches := map[string]string{}
				parseOUI(string(raw), patches)
				for k, v := range patches {
					if ouiCache[k] == "" {
						ouiCache[k] = v
					}
				}
			}
		}
		// Per-user files override (the operator's corrections always win).
		for _, p := range userUI() {
			if raw, err := os.ReadFile(p); err == nil {
				parseOUI(string(raw), ouiCache)
			}
		}
	})
	return ouiCache
}

// externalUI lists registry files checked after the embedded snapshot, in
// increasing precedence: system knowledge files only fill prefixes the
// embedded table lacks (their names are often truncated), while the per-user
// files may override anything.
func externalUI() []string { return append(systemUI(), userUI()...) }

func systemUI() []string {
	return []string{
		"/usr/share/arp-scan/ieee-oui.txt",
		"/usr/share/arp-scan/oui.txt",
		"/usr/share/nmap/nmap-mac-prefixes",
		"/usr/share/ieee-data/oui.txt",
	}
}

func userUI() []string {
	home, _ := os.UserHomeDir()
	paths := []string{}
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
		// nmap-mac-prefixes (and trimmed IEEE copies) put the prefix, some
		// whitespace, then the vendor: "B827EB   Raspberry Pi Foundation".
		if hex == "" {
			f := strings.Fields(line)
			if len(f) >= 2 && len(cleanPrefix(f[0])) == 6 {
				hex = cleanPrefix(f[0])
				vendor = strings.TrimSpace(line[strings.Index(line, f[0])+len(f[0]):])
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
	if ctx.Err() != nil {
		return "" // already stopping; do not start a lookup at all
	}
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
	limit, ok := boundUntil(ctx, 800*time.Millisecond)
	if !ok {
		return "", false
	}
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
	_ = conn.SetWriteDeadline(limit)
	if _, err := conn.Write(b.Bytes()); err != nil {
		return "", false
	}
	buf := make([]byte, 4096)
	for {
		// Read in slices with a context re-check: this runs once per host, so
		// a fixed deadline would make Ctrl+C in a live sweep wait out the
		// remaining hosts one after another.
		if time.Now().After(limit) {
			return "", false
		}
		_ = conn.SetReadDeadline(time.Now().Add(shortRead))
		n, err := conn.Read(buf)
		if err != nil {
			if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
				if ctx.Err() != nil {
					return "", false
				}
				continue
			}
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

// boundUntil returns the earlier of the context's deadline and now+d, and
// reports false when the context is already done. A context that carries only
// cancellation and no deadline must still end the wait promptly: falling back
// to a flat d leaves a Ctrl+C in a live watch unanswered for the whole window,
// once per host.
func boundUntil(ctx context.Context, d time.Duration) (time.Time, bool) {
	if ctx.Err() != nil {
		return time.Time{}, false
	}
	limit := time.Now().Add(d)
	if dl, has := ctx.Deadline(); has && dl.Before(limit) {
		return dl, true
	}
	return limit, true
}

// shortRead bounds a single read inside a wait loop, so the loop can re-check
// the context often enough for a cancel to be noticed at once without spinning.
const shortRead = 50 * time.Millisecond

// BrowseMDNS works through the whole candidate list at once to name hosts that
// ignored a one-by-one query: it fires a reverse-PTR probe at every address,
// joins the multicast group, then listens briefly for PTR and A records. The
// returned map is ip -> .local hostname (first name wins, only for addresses
// the caller asked about). Nothing blocks longer than the context bound
// (default <1s), and everything still works with no mDNS daemon installed.
func BrowseMDNS(ctx context.Context, ips []string) map[string]string {
	names := map[string]string{}
	if len(ips) == 0 {
		return names
	}
	group := net.IPv4(224, 0, 0, 251)
	conn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{IP: group, Port: 5353})
	if err != nil {
		// No group membership (no root / no interface): fall back to unicast
		// responses by sending from an ephemeral socket, like reverseMDNS.
		conn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: group, Port: 5353})
		if err != nil {
			return names
		}
	}
	defer conn.Close()

	limit, ok := boundUntil(ctx, 700*time.Millisecond)
	if !ok {
		return names
	}
	_ = conn.SetWriteDeadline(limit)

	for _, ip := range ips {
		if names[ip] != "" {
			continue
		}
		_, _ = conn.Write(reversePTRQuery(ip))
	}

	buf := make([]byte, 4096)
	for {
		// Read in short slices rather than parking on one deadline: the
		// context can be cancelled at any moment, and only a re-check between
		// reads notices it.
		if time.Now().After(limit) {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(shortRead))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
				if ctx.Err() != nil {
					break // asked to stop
				}
				continue // slice elapsed, keep listening until the limit
			}
			break
		}
		for _, rr := range mdnsRRs(buf[:n]) {
			switch {
			case rr.typ == 12 && rr.target != "" && isLocalname(rr.target):
				if ip, ok := arpaToIP(rr.owner); ok {
					if names[ip] == "" {
						names[ip] = rr.target
					}
				}
			case rr.typ == 1 && rr.ip != nil && isLocalname(rr.owner):
				s := rr.ip.String()
				for _, ip := range ips {
					if ip == s && names[ip] == "" {
						names[ip] = rr.owner
					}
				}
			case rr.typ == 28 && rr.ip != nil && isLocalname(rr.owner):
				// AAAA-only hosts are rare on v4 LANs but appear; skip mapping
				// since gnulte sweeps IPv4 only.
			}
		}
	}
	// The question section carries the reverse names too; keep them out of
	// the result set (callers asked for live addresses only, which is what
	// mdnsPTR answers already handle). No further work needed.
	return names
}

// reversePTRQuery builds a PTR probe for ip's .arpa name with the
// UnicastResponse bit, mirroring what reverseMDNS sends.
func reversePTRQuery(ip string) []byte {
	ip4 := net.ParseIP(ip)
	if ip4 == nil || ip4.To4() == nil {
		return nil
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
	return b.Bytes()
}

// ----- DNS-SD service discovery (mDNS, Avahi-style) -----

// serviceType is one DNS-SD service type we probe for: the multicast service
// name (e.g. "_airplay._tcp.local.") and the short label shown in scan rows.
type serviceType struct {
	name  string
	label string
}

// serviceTypes is the curated set of places mDNS/DNS-SD responders (Avahi,
// macOS, Windows, Linux, IoT firmware) advertise services. Probing all of
// them is one small multicast packet (kept under the usual ~1.4KB UDP limit),
// and only these labels ever reach the device table — unrelated noise on the
// channel is ignored.
var serviceTypes = []serviceType{
	{"_airplay._tcp.local.", "airplay"},
	{"_raop._tcp.local.", "airplay-audio"},
	{"_googlecast._tcp.local.", "chromecast"},
	{"_spotify-connect._tcp.local.", "spotify"},
	{"_hap._tcp.local.", "homekit"},
	{"_matter._tcp.local.", "matter"},
	{"_meshcop._udp.local.", "thread"},
	{"_companion-link._tcp.local.", "apple-connect"},
	{"_ssh._tcp.local.", "ssh"},
	{"_http._tcp.local.", "http"},
	{"_https._tcp.local.", "https"},
	{"_smb._tcp.local.", "smb"},
	{"_afpovertcp._tcp.local.", "afp"},
	{"_workstation._tcp.local.", "workstation"},
	{"_printer._tcp.local.", "printer"},
	{"_ipp._tcp.local.", "ipp"},
	{"_scanner._tcp.local.", "scanner"},
	{"_pdl-datastream._tcp.local.", "pdl"},
	{"_rtsp._tcp.local.", "rtsp"},
	{"_onvif._tcp.local.", "onvif"},
	{"_rfb._tcp.local.", "vnc"},
	{"_rdp._tcp.local.", "rdp"},
	{"_mobile-device._tcp.local.", "mobile-sync"},
	{"_nut._tcp.local.", "ups"},
}

// serviceLabel maps a full service name ("_airplay._tcp.local") to its short
// label, built once so the membership test stays cheap.
var serviceLabel = func() map[string]string {
	m := make(map[string]string, len(serviceTypes))
	for _, s := range serviceTypes {
		m[strings.TrimSuffix(s.name, ".")] = s.label
	}
	return m
}()

// ServiceLabels asks the LAN's mDNS/DNS-SD responders (Avahi and friends) what
// services each candidate address offers, and returns ip -> short labels. It
// runs a two-phase multicast exchange: PTR probes for every known service
// type, then SRV/A probes for any instance the first answer burst did not map
// to an address. Responders that stay silent contribute nothing; the whole
// probe is bounded by the context (default under two seconds) and needs no
// mDNS daemon of our own.
func ServiceLabels(ctx context.Context, ips []string) map[string][]string {
	out := map[string][]string{}
	if len(ips) == 0 {
		return out
	}
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip] = true
	}
	conn, err := listenMDNS()
	if err != nil {
		return out
	}
	defer conn.Close()

	var rrs []mdnsRR
	collect := func(q []byte) {
		budget := serviceBudget(ctx)
		if budget <= 0 {
			return // the caller is stopping
		}
		limit := time.Now().Add(budget)
		_ = conn.SetWriteDeadline(limit)
		if _, err := conn.Write(q); err != nil {
			return
		}
		buf := make([]byte, 8192)
		for {
			// Sliced reads with a context re-check, so an interrupt ends the
			// listen instead of sitting out the phase budget.
			if time.Now().After(limit) {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(shortRead))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				return
			}
			rrs = append(rrs, mdnsRRs(buf[:n])...)
		}
	}

	// Phase 1: every known service type in one PTR packet.
	collect(serviceQueryPacket())

	// Figure out what phase 1 still left dangling: instances without a host
	// (no SRV yet) and hosts without an address (no A yet).
	hostIP := map[string]string{}
	instanceHost := map[string]string{}
	for _, rr := range rrs {
		switch rr.typ {
		case 1:
			if rr.ip != nil && rr.owner != "" {
				hostIP[rr.owner] = rr.ip.String()
			}
		case 33:
			if rr.owner != "" && rr.target != "" {
				instanceHost[rr.owner] = rr.target
			}
		}
	}
	instances := map[string]bool{}     // instance names advertised in PTRs
	instanceSvc := map[string]string{} // instance name -> label
	for _, rr := range rrs {
		if rr.typ != 12 || rr.target == "" {
			continue
		}
		label, ok := serviceLabel[strings.TrimSuffix(rr.owner, ".")]
		if !ok {
			continue
		}
		instances[rr.target] = true
		instanceSvc[rr.target] = label
	}

	// Phase 2: resolve what is still missing, in a second packet.
	if len(instances) > 0 {
		var srvQ, aQ []string
		for inst := range instances {
			if hostIP[inst] == "" && instanceHost[inst] == "" {
				srvQ = append(srvQ, inst)
			}
		}
		for _, host := range instanceHost {
			host = strings.TrimSuffix(host, ".")
			if hostIP[host] == "" {
				aQ = append(aQ, host)
			}
		}
		sort.Strings(srvQ)
		sort.Strings(aQ)
		if len(srvQ)+len(aQ) > 0 {
			collect(buildServiceQueries(srvQ, aQ))
		}
	}

	// Rebuild the address maps with phase 2 answers included.
	hostIP = map[string]string{}
	instanceHost = map[string]string{}
	for _, rr := range rrs {
		switch rr.typ {
		case 1:
			if rr.ip != nil && rr.owner != "" {
				hostIP[rr.owner] = rr.ip.String()
			}
		case 33:
			if rr.owner != "" && rr.target != "" {
				instanceHost[rr.owner] = rr.target
			}
		}
	}

	// Every advertised instance resolves to the address that hosts it, either
	// directly (an A record whose owner is the instance) or through its SRV
	// target host.
	for inst, label := range instanceSvc {
		ip := ""
		switch {
		case hostIP[inst] != "":
			ip = hostIP[inst]
		case instanceHost[inst] != "":
			ip = hostIP[strings.TrimSuffix(instanceHost[inst], ".")]
		}
		if ip == "" || !want[ip] {
			continue
		}
		out[ip] = append(out[ip], label)
	}
	for ip, labels := range out {
		sort.Strings(labels)
		seen := labels[:0]
		for i, l := range labels {
			if i == 0 || l != labels[i-1] {
				seen = append(seen, l)
			}
		}
		out[ip] = seen
	}
	return out
}

// listenMDNS opens the multicast socket used for service discovery, falling
// back to an ephemeral unicast socket when group membership is unavailable.
func listenMDNS() (*net.UDPConn, error) {
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", nil, group)
	if err == nil {
		return conn, nil
	}
	return net.DialUDP("udp4", nil, group)
}

// serviceBudget bounds one phase of the service probe by the context's
// deadline, defaulting to 900ms on a context without one. A context that is
// already cancelled yields zero, which is how the caller learns to stop
// instead of listening out a phase nobody is waiting for.
func serviceBudget(ctx context.Context) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < 900*time.Millisecond {
			return rem
		}
	}
	return 900 * time.Millisecond
}

// serviceQueryPacket builds one mDNS packet asking for the PTR record of every
// known service type at once, with the UnicastResponse bit on each question so
// responders answer straight back to our socket.
func serviceQueryPacket() []byte {
	b := &bytes.Buffer{}
	b.Write([]byte{0, 0, 0, 0, byte(len(serviceTypes) >> 8), byte(len(serviceTypes)), 0, 0, 0, 0, 0, 0})
	for _, s := range serviceTypes {
		writeName(b, s.name)
		b.Write([]byte{0, 12, 0x80, 0x01}) // qtype PTR, qclass IN + UnicastResponse
	}
	return b.Bytes()
}

// buildServiceQueries builds one multicast packet of SRV and A probes (with
// the UnicastResponse bit) for instances and hosts phase 1 left unresolved.
func buildServiceQueries(instances, hosts []string) []byte {
	b := &bytes.Buffer{}
	n := len(instances) + len(hosts)
	b.Write([]byte{0, 0, 0, 0, byte(n >> 8), byte(n), 0, 0, 0, 0, 0, 0})
	for _, inst := range instances {
		writeName(b, inst)
		b.Write([]byte{0, 33, 0x80, 0x01}) // qtype SRV
	}
	for _, h := range hosts {
		writeName(b, h)
		b.Write([]byte{0, 1, 0x80, 0x01}) // qtype A
	}
	return b.Bytes()
}

func isLocalname(s string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSuffix(s, ".")), ".local")
}

func arpaToIP(owner string) (string, bool) {
	p := strings.Split(strings.ToLower(strings.TrimSuffix(owner, ".")), ".")
	if len(p) != 6 || p[4] != "in-addr" || p[5] != "arpa" {
		return "", false
	}
	var oct [4]int
	for i := 0; i < 4; i++ {
		n, err := strconv.Atoi(p[3-i])
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		oct[i] = n
	}
	return fmt.Sprintf("%d.%d.%d.%d", oct[0], oct[1], oct[2], oct[3]), true
}

// mdnsRR is one parsed resource record from an mDNS packet.
type mdnsRR struct {
	owner  string
	typ    uint16
	target string // PTR/SRV target name (no trailing dot)
	ip     net.IP // A/AAAA address
}

// mdnsRRs walks an mDNS/DNS reply, extracting PTR, SRV, A and AAAA records so
// hostname collection works from any packet the group sends us.
func mdnsRRs(pkt []byte) []mdnsRR {
	if len(pkt) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	ns := int(binary.BigEndian.Uint16(pkt[8:10]))
	ar := int(binary.BigEndian.Uint16(pkt[10:12]))
	pos := 12
	var out []mdnsRR
	for i := 0; i < qd; i++ {
		_, n, ok := skipName(pkt, pos)
		if !ok {
			return nil
		}
		pos = n + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		owner, n, ok := skipName(pkt, pos)
		if !ok {
			return out
		}
		pos = n
		if pos+10 > len(pkt) {
			return out
		}
		rt := binary.BigEndian.Uint16(pkt[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[pos+8 : pos+10]))
		pos += 10
		rdStart := pos
		if rdStart+rdlen > len(pkt) {
			return out
		}
		rr := mdnsRR{owner: strings.TrimSuffix(owner, "."), typ: rt}
		switch rt {
		case 1: // A
			if rdlen >= 4 {
				rr.ip = net.IPv4(pkt[rdStart], pkt[rdStart+1], pkt[rdStart+2], pkt[rdStart+3]).To4()
			}
		case 28: // AAAA
			if rdlen >= 16 {
				rr.ip = net.IP(append([]byte(nil), pkt[rdStart:rdStart+16]...))
			}
		case 12: // PTR
			if t, _, ok := skipName(pkt, rdStart); ok {
				rr.target = strings.TrimSuffix(t, ".")
			}
		case 33: // SRV
			if rdlen >= 6 {
				if t, _, ok := skipName(pkt, rdStart+6); ok {
					rr.target = strings.TrimSuffix(t, ".")
				}
			}
		}
		out = append(out, rr)
		pos = rdStart + rdlen
	}
	return out
}

// NetBIOSName asks a host for its NetBIOS name via an NBSTAT query on UDP 137
// (RFC 1002). Windows machines and many IoT devices that ignore DNS and
// mDNS still answer this. Bound to a second when no reply arrives; nil result
// is not an error.
func NetBIOSName(ctx context.Context, ip string) string {
	limit, ok := boundUntil(ctx, 900*time.Millisecond)
	if !ok {
		return ""
	}
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ip, "137"))
	if err != nil {
		return ""
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 137})
	if err != nil {
		// Port 137 needs root (or is taken): answer on any local port.
		conn, err = net.ListenUDP("udp4", nil)
		if err != nil {
			return ""
		}
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(limit)
	if _, err := conn.WriteToUDP(nbstatQuery(), raddr); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	for {
		// Short reads with a context re-check, so an interrupt ends the wait
		// instead of running out the full second per host.
		if time.Now().After(limit) {
			return ""
		}
		_ = conn.SetReadDeadline(time.Now().Add(shortRead))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, isNet := err.(net.Error); isNet && ne.Timeout() {
				if ctx.Err() != nil {
					return ""
				}
				continue
			}
			return ""
		}
		if name, ok := nbstatReply(buf[:n]); ok {
			return name
		}
	}
}

// nbstatQuery builds a Name-Service Status ("NBSTAT", opcode 0x21) query for
// the wildcard name, which asks the host to report all its registered names.
func nbstatQuery() []byte {
	tid := uint16(time.Now().UnixNano())
	b := &bytes.Buffer{}
	b.Write([]byte{byte(tid >> 8), byte(tid), 0, 0x10, 0, 1, 0, 0, 0, 0, 0, 0})
	// First-level encoded "*" + 14 spaces + suffix 0x00 (returns NBSTAT rdata).
	raw := make([]byte, 16)
	raw[0] = '*'
	for i := 1; i < 15; i++ {
		raw[i] = ' '
	}
	b.WriteByte(0x20)
	for _, c := range raw {
		b.WriteByte(c>>4 + 0x41)
		b.WriteByte(c&0x0F + 0x41)
	}
	b.Write([]byte{0, 0x21, 0, 1}) // qtype NBSTAT, qclass IN
	return b.Bytes()
}

// nbstatReply extracts a computer name from an NBSTAT response. Tricky
// records (ADRESS_NOT_FOUND, error suffixes) are ignored.
func nbstatReply(pkt []byte) (string, bool) {
	if len(pkt) < 12 {
		return "", false
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	pos := 12
	for i := 0; i < qd; i++ {
		_, n, ok := skipName(pkt, pos)
		if !ok {
			return "", false
		}
		pos = n + 4
	}
	for i := 0; i < an; i++ {
		_, n, ok := skipName(pkt, pos)
		if !ok {
			return "", false
		}
		pos = n
		if pos+10 > len(pkt) {
			return "", false
		}
		rt := binary.BigEndian.Uint16(pkt[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[pos+8 : pos+10]))
		pos += 10
		if rdlen < 1 || pos+rdlen > len(pkt) {
			return "", false
		}
		if rt != 0x21 { // NBSTAT
			pos += rdlen
			continue
		}
		names := parseNBSTAT(pkt[pos : pos+rdlen])
		if len(names) == 0 {
			return "", false
		}
		return names[0], true
	}
	return "", false
}

func parseNBSTAT(rdata []byte) []string {
	if len(rdata) < 1 {
		return nil
	}
	num := int(rdata[0])
	pos := 1
	var bySuffix []struct {
		name string
		suf  uint16
	}
	for i := 0; i < num; i++ {
		if pos+20 > len(rdata) {
			break
		}
		name := strings.TrimRight(string(rdata[pos:pos+16]), " \x00")
		suf := binary.BigEndian.Uint16(rdata[pos+16 : pos+18])
		pos += 20
		// Skip "*" and error/control names; keep workstation/server entries
		// and prefer the file-server (<20>) registration over the plain
		// workstation (<00>) one, as most stacks register both.
		if name == "" || name == "*" || suffixGroup(suf) != 0 {
			continue
		}
		bySuffix = append(bySuffix, struct {
			name string
			suf  uint16
		}{name, suf})
	}
	for _, key := range []uint16{0x20, 0x00} {
		for _, e := range bySuffix {
			if e.suf == key {
				return []string{e.name}
			}
		}
	}
	return nil
}

func suffixGroup(sf uint16) int {
	switch sf {
	case 0x00, 0x20: // workstation, file server
		return 0
	case 0x1C, 0x1D: // domain controller, master browser
		return 2
	case 0x03: // messenger
		return 0
	}
	return 1
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
		strings.Contains(n, "imac") || strings.Contains(n, "macbook") ||
		strings.Contains(n, "homepod") || strings.Contains(n, "apple tv"):
		return "Apple device"
	case strings.Contains(v, "samsung") || strings.Contains(v, "xiaomi") ||
		strings.Contains(v, "oneplus") || strings.Contains(v, "motorola") ||
		strings.Contains(v, "huawei") || strings.Contains(v, "google") ||
		strings.Contains(v, "oppo") || strings.Contains(v, "vivo") ||
		strings.Contains(v, "realme") || strings.Contains(n, "android") ||
		strings.Contains(n, "galaxy") || strings.Contains(n, " phone") ||
		strings.Contains(n, "pixel"):
		return "Mobile"
	case strings.Contains(v, "lg") || strings.Contains(v, "sony") ||
		strings.Contains(v, "tcl") || strings.Contains(v, "hisense") ||
		strings.Contains(v, "philips") || strings.Contains(v, "vizio") ||
		strings.Contains(v, "amazon") || strings.Contains(v, "sonos") ||
		strings.Contains(v, "roku") || strings.Contains(v, "harman") ||
		strings.Contains(n, "tv") || strings.Contains(n, "smarttv") ||
		strings.Contains(n, "roku") || strings.Contains(n, "echo") ||
		strings.Contains(n, "alexa") || strings.Contains(n, "nest") ||
		strings.Contains(n, "chromecast") || strings.Contains(n, "firetv") ||
		strings.Contains(n, "homepod"):
		return "Media/TV"
	case strings.Contains(v, "espressif") || strings.Contains(v, "turbo-x") ||
		strings.Contains(v, "securifi") || strings.Contains(v, "tuya") ||
		strings.Contains(v, "jemiot") || strings.Contains(v, "silicon labs") ||
		strings.Contains(v, "nordic") ||
		strings.Contains(n, "wemo") || strings.Contains(n, "smartbulb") ||
		strings.Contains(n, "smartplug") || strings.Contains(n, "smart socket") ||
		strings.Contains(n, "plug-") || strings.Contains(n, "bulb"):
		return "IoT (smart home)"
	case strings.Contains(v, "hikvision") || strings.Contains(v, "dahua") ||
		strings.Contains(v, "reolink") || strings.Contains(v, "ezviz") ||
		strings.Contains(v, "amcrest") || strings.Contains(v, "axis communications") ||
		strings.Contains(n, "cam-") || strings.Contains(n, "camera") ||
		strings.Contains(n, "nvr") || strings.Contains(n, "dvr"):
		return "Camera/NVR"
	case strings.Contains(v, "canon") || strings.Contains(v, "epson") ||
		strings.Contains(v, "brother") || strings.Contains(v, "xerox") ||
		strings.Contains(v, "ricoh") || strings.Contains(v, "zebra") ||
		strings.Contains(v, "hewlett-packard") || strings.Contains(v, " hp") ||
		strings.Contains(n, "printer") || strings.Contains(n, "print") ||
		strings.Contains(n, "scanner"):
		return "Printer"
	case strings.Contains(v, "tp-link") || strings.Contains(v, "asus") ||
		strings.Contains(v, "netgear") || strings.Contains(v, "linksys") ||
		strings.Contains(v, "d-link") || strings.Contains(v, "dlink") ||
		strings.Contains(v, "totolink") || strings.Contains(v, "belkin") ||
		strings.Contains(v, "zyxel") || strings.Contains(v, "ubiquiti") ||
		strings.Contains(v, "mikrotik") || strings.Contains(v, "cisco") ||
		strings.Contains(v, "aruba") || strings.Contains(v, "ubnt"):
		return "Router/AP"
	case strings.Contains(n, "router") || strings.Contains(n, "openwrt") ||
		strings.Contains(n, "gateway") || strings.Contains(n, "ap-") ||
		strings.Contains(n, "accesspoint") || strings.Contains(n, "routeur"):
		return "Router/AP"
	case strings.Contains(v, "raspberry") || strings.Contains(v, "arduino"):
		return "Raspberry Pi"
	case strings.Contains(v, "microsoft") || strings.Contains(v, "intel") ||
		strings.Contains(v, "dell") || strings.Contains(v, "lenovo") ||
		strings.Contains(v, "hewlett") || strings.Contains(v, "acer") ||
		strings.Contains(v, "aopen") || strings.Contains(v, "gigabyte") ||
		strings.Contains(v, "msi") || strings.Contains(n, "windows") ||
		strings.Contains(n, "desktop") || strings.Contains(n, "laptop") ||
		strings.Contains(n, "workstation") || strings.Contains(n, "nas"):
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
	case isOpen(1883) || isOpen(8883) || isOpen(4840):
		return "IoT"
	case isOpen(554) || isOpen(8554) || isOpen(8555):
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
