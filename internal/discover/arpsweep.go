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

package discover

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// sweepWindow is how long one round of the sweep listens for replies once
	// its questions are out. The old shell-out asked one who-has per host and
	// gave each 2 s; here every question is asked within milliseconds of the
	// others, so one window covers the sweep without stretching it to
	// N × timeout.
	sweepWindow = 2 * time.Second

	// sweepRounds is how many ask rounds a silent address gets. Real hosts
	// answer the first who-has; one dropped frame in a busy segment should not
	// cost a device.
	sweepRounds = 2

	// sweepIdle is the pause when the socket has nothing waiting. The socket is
	// non-blocking, so the reader paces itself instead of spinning.
	sweepIdle = 3 * time.Millisecond

	// sweepRetryGap is the pause between asking rounds.
	sweepRetryGap = 400 * time.Millisecond

	// resolveWindow bounds one wait when resolving a single address. One
	// question deserves less patience than a whole sweep.
	resolveWindow = 700 * time.Millisecond

	// resolveRounds is how many times a single address is asked. Two, because a
	// dropped first frame must not decide whether a victim's MAC resolves — and
	// a target that ignores ARP costs only this much before the engine gives up.
	resolveRounds = 2

	// sweepThreadCap bounds concurrent who-has sends. A /24 is 254 tiny frames
	// of one syscall each, so this only stops an absurd -t from letting a
	// single sweep flood the segment.
	sweepThreadCap = 256
)

// sweepResult is what an ARP sweep learned: every address that answered, and
// the MAC it answered with. Both matter — the IP list is what a scan reports as
// alive, the MAC is what it reports per host.
type sweepResult struct {
	live []string          // sorted addresses that answered
	macs map[string]string // address -> upper-case MAC
}

// ARPSweep asks every target "who has this address" by putting real who-has
// frames on the wire and listening for the answers, catching hosts that answer
// ARP but filter ICMP echo — common on phones, smart TVs and IOT. It needs raw
// sockets, so it only works as root; run gnulte-scan with sudo to enable it.
// Returns the sorted list of hosts that answered.
func ARPSweep(ctx context.Context, targets []string, iface string, threads int, onProgress ...func(completed, alive int)) []string {
	if !Privileged() || len(targets) == 0 || iface == "" {
		return nil
	}
	var report func(completed, alive int)
	if len(onProgress) > 0 {
		report = onProgress[0]
	}
	return runSweep(ctx, targets, iface, threads, report).live
}

// ResolveMAC asks one address who it is and returns its MAC, over the same raw
// socket the sweep uses. This replaces the `arping -c 1` shell-out the engine
// used to resolve target addresses: a victim that filters ping but answers ARP
// still resolves, with no helper binary installed.
func ResolveMAC(ctx context.Context, iface, ip string) (net.HardwareAddr, error) {
	if !Privileged() {
		return nil, errors.New("ARP resolution needs root (raw sockets)")
	}
	if iface == "" {
		return nil, errors.New("no interface given for ARP resolution")
	}
	return resolveOne(ctx, iface, ip)
}

// addrProbe is one who-has question plus the answer state that goes with it.
type addrProbe struct {
	ip       string
	mac      net.HardwareAddr
	answered bool
}

// probeSet holds every address under sweep. Keeping answer bookkeeping separate
// from the socket makes "is this reply worth crediting?" a pure function, so it
// is testable without root and without a live segment.
type probeSet struct {
	selfMAC net.HardwareAddr
	selfIP  string
	order   []string              // ask order, for stable output
	probes  map[string]*addrProbe // by address
}

// newProbeSet indexes targets, dropping anything unusable and our own address
// (our who-has comes back to us and must never be counted as a found host).
func newProbeSet(targets []string, selfMAC net.HardwareAddr, selfIP string) *probeSet {
	ps := &probeSet{
		selfMAC: selfMAC,
		selfIP:  selfIP,
		probes:  make(map[string]*addrProbe, len(targets)),
	}
	for _, raw := range targets {
		parsed := net.ParseIP(strings.TrimSpace(raw))
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		norm := parsed.To4().String()
		if norm == selfIP {
			continue
		}
		if _, dup := ps.probes[norm]; dup {
			continue
		}
		ps.probes[norm] = &addrProbe{ip: norm}
		ps.order = append(ps.order, norm)
	}
	return ps
}

// note records a reply and reports whether it was the first useful answer for
// that address. It declines — no state change, no count — for a reply that must
// not be credited: an address nobody asked about, a repeat from an address that
// already answered, our own echo, or a MAC that cannot identify a host
// (all-zero, broadcast, or multicast).
func (ps *probeSet) note(fromMAC net.HardwareAddr, fromIP net.IP) bool {
	if len(fromMAC) != 6 || fromIP == nil || fromIP.To4() == nil {
		return false
	}
	p, ok := ps.probes[fromIP.To4().String()]
	if !ok || p.answered {
		return false
	}
	if !usableMAC(fromMAC) || sameMAC(fromMAC, ps.selfMAC) {
		return false
	}
	p.answered = true
	p.mac = fromMAC
	return true
}

// pending lists the addresses still waiting for a first answer, in ask order.
func (ps *probeSet) pending() []string {
	var out []string
	for _, ip := range ps.order {
		if !ps.probes[ip].answered {
			out = append(out, ip)
		}
	}
	return out
}

// settled reports whether every asked address has answered.
func (ps *probeSet) settled() bool {
	if len(ps.order) == 0 {
		return false
	}
	for _, ip := range ps.order {
		if !ps.probes[ip].answered {
			return false
		}
	}
	return true
}

// live is how many addresses have answered so far.
func (ps *probeSet) live() int {
	n := 0
	for _, ip := range ps.order {
		if ps.probes[ip].answered {
			n++
		}
	}
	return n
}

// collect returns the sorted live addresses with their MACs, preferring the MAC
// off the wire and falling back to the kernel's view. The reply also reaches the
// network stack, so the proc table normally has it too; the fallback covers the
// race where the table has not been written yet.
func (ps *probeSet) collect(iface string) sweepResult {
	res := sweepResult{macs: make(map[string]string, len(ps.order))}
	for _, ip := range ps.order {
		p := ps.probes[ip]
		if !p.answered {
			continue
		}
		res.live = append(res.live, ip)
		if mac := strings.ToUpper(p.mac.String()); !allZeroMAC(p.mac) {
			res.macs[ip] = mac
		} else if mac := procARPMAC(iface, ip); mac != "" {
			res.macs[ip] = mac
		}
	}
	sort.Strings(res.live)
	return res
}

// usableMAC reports whether a MAC can identify a host: the all-zero placeholder
// from an unanswered who-has, the broadcast address, and multicast group
// addresses identify nobody.
func usableMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	if allZeroMAC(mac) || sameMAC(mac, broadcastMAC) {
		return false
	}
	return mac[0]&1 == 0 // unicast: even first octet
}

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func allZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func sameMAC(a, b net.HardwareAddr) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// subnetTargets lists the other usable addresses on an interface's own subnet.
// An empty result means "don't sweep".
func subnetTargets(iface string) []string {
	nif, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, err := nif.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if _, ipnet, err := net.ParseCIDR(a.String()); err == nil {
			if hosts := hostsInNet(ipnet); len(hosts) > 0 {
				return hosts
			}
		}
	}
	return nil
}

// hostsInNet expands a subnet to the addresses worth asking about, skipping the
// network and broadcast addresses, and refusing anything too large to sweep as a
// side effect of a neighbour lookup. The cap is the safety rail: an interface
// with a sparse /16 or a fat /8 must not turn a name lookup into a
// segment-wide flood, so it yields nothing and the caller falls back to the
// kernel table.
func hostsInNet(ipnet *net.IPNet) []string {
	ones, bits := ipnet.Mask.Size()
	// bits != 32 means a non-IPv4 (or malformed) mask: nothing to expand.
	// A /31 or /32 has no other address at all.
	if bits != 32 || ones > 30 {
		return nil
	}
	size := uint32(1) << uint(bits-ones)
	// Compare the *host* count, not the address count: the two network
	// addresses are never asked about, so a /22 is 1022 questions.
	if size < 2 || size-2 > maxNeighborSweep {
		return nil
	}
	base := ipnet.IP.To4()
	if base == nil {
		return nil
	}
	base = base.Mask(ipnet.Mask)
	out := make([]string, 0, size-2)
	for i := uint32(1); i < size-1; i++ {
		probe := make(net.IP, 4)
		binary.BigEndian.PutUint32(probe, binary.BigEndian.Uint32(base)+i)
		out = append(out, probe.String())
	}
	return out
}

// maxNeighborSweep caps how many addresses an implicit neighbour sweep may ask
// about. /22 is 1022 addresses, which covers the residential and small-office
// segments this toolkit is used on without ever flooding a large network.
const maxNeighborSweep = 1022

// procARPMAC reads one address's MAC out of the kernel ARP table. Used as the
// fallback when a reply's sender MAC is unusable but the stack resolved it.
func procARPMAC(iface, ip string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] != ip {
			continue
		}
		if iface != "" && f[5] != iface {
			continue
		}
		if mac := f[3]; mac != "" && !allZeroMAC(net.HardwareAddr(mustParseMAC(mac))) {
			return strings.ToUpper(mac)
		}
	}
	return ""
}

func mustParseMAC(s string) []byte {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return hw
}
