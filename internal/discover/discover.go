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

// Package discover performs LAN host discovery: a parallel ICMP sweep via the
// system `ping`, neighbor resolution from /proc/net/arp (boosted, as root, by
// the in-Go ARP sweep in arpsweep.go, which learns devices the kernel table
// never sees), vendor identification, and hostname resolution. `-d/--deep`
// additionally runs the in-Go port scanner against alive hosts.
//
// The ARP half needs no helper binary: who-has frames are crafted and read
// in-process over AF_PACKET, so arping/arp-scan are not required anywhere.
package discover

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"gnulte-go/internal/ident"
)

// Row is one discovered host.
type Row struct {
	IP       string
	MAC      string
	Vendor   string
	Hostname string
	Type     string
	Ports    string
	OS       string
	OSConf   int // confidence 0-100 from deep scan
	Uptime   string
	Banners  []string
	Services []string // mDNS/DNS-SD service labels (Avahi-style discovery)
	ScanNote string
	IsSelf   bool
	IsNew    bool
}

// PingSweep tests every IP with `ping -c1 -W1 -n`, in parallel, honoring
// threads. Returns the sorted list of live addresses. An optional progress
// callback receives (completed, alive) counts as probes finish.
func PingSweep(ctx context.Context, targets []string, threads int, onProgress ...func(completed, alive int)) []string {
	if threads < 1 {
		threads = 1
	}
	// Cap concurrency: 100k concurrent ping subprocesses must never happen,
	// even if the operator passes -t 100000.
	if threads > 512 {
		threads = 512
	}
	jobs := make(chan string)
	var live []string
	var mu sync.Mutex
	var completed, alive int
	report := func(d, a int) {
		if len(onProgress) > 0 && onProgress[0] != nil {
			onProgress[0](d, a)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ok := ipAlive(ctx, ip)
				mu.Lock()
				completed++
				if ok {
					live = append(live, ip)
					alive++
				}
				report(completed, alive)
				mu.Unlock()
			}
		}()
	}
	for _, ip := range targets {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	sort.Strings(live)
	return live
}

func ipAlive(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", "-n", ip)
	err := cmd.Run()
	return err == nil
}

// Privileged reports whether we can open raw sockets (root, or a capability
// override). ARP probing and frame injection need it; everything else degrades.
func Privileged() bool { return os.Geteuid() == 0 }

// Neighbors returns ip->MAC from /proc/net/arp, optionally restricted to one
// interface (empty = all). This is the cheap read: what the kernel already
// learned, with no packets sent. Callers that are about to sweep anyway should
// use DiscoverNeighbors, which also asks the segment directly.
func Neighbors(ctx context.Context, iface string) map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		if iface != "" && fields[5] != iface {
			continue
		}
		if net.ParseIP(fields[0]) == nil {
			continue
		}
		if mac := fields[3]; mac != "" && mac != "00:00:00:00:00:00" {
			out[fields[0]] = strings.ToUpper(mac)
		}
	}
	return out
}

// DiscoverNeighbors is the thorough form of Neighbors: on top of the kernel's
// table it asks the interface's own subnet directly, so devices that answer ARP
// but never originate unicast traffic — phones in doze, printers, TVs — are
// learned too. This is what the old `arp-scan --localnet` boost did, and it
// needs no helper binary, only raw sockets (so only as root; otherwise it
// degrades to a plain table read).
//
// It costs a few seconds of wire time, so it belongs in a discovery pass, not in
// a hot loop that only wants an address looked up.
func DiscoverNeighbors(ctx context.Context, iface string) map[string]string {
	out := Neighbors(ctx, iface)
	if iface == "" || !Privileged() {
		return out
	}
	// One pass, no retry round: this lookup is a bonus on top of the kernel
	// table, not the user's reason for running the tool.
	res := sweep(ctx, subnetTargets(iface), iface, neighborSweepThreads, 1, nil)
	// Merge without overwriting: the kernel's own entry is authoritative where
	// the two disagree (a sweep answer for a stale address is possible if the
	// device was reassigned mid-sweep).
	for ip, mac := range res.macs {
		if _, known := out[ip]; !known {
			out[ip] = mac
		}
	}
	return out
}

// neighborSweepThreads bounds the implicit sweep inside DiscoverNeighbors. It has
// no -t of its own, so this is a fixed, polite number: enough that a /24 is
// asked quickly, low enough that nothing resembling a flood goes out.
const neighborSweepThreads = 32

// VendorFor maps a MAC (upper hex, any separator) to a vendor name, using the
// embedded IEEE registry (with any local oui.txt layered on top).
func VendorFor(mac string) string {
	return ident.Vendor(mac)
}

// ResolveHost finds a device's name: reverse DNS first, then a .local mDNS
// lookup, both time-bounded so a LAN without a reverse zone cannot stall the
// scan (falls back gracefully).
func ResolveHost(ctx context.Context, ip string) string {
	return ident.Hostname(ctx, ip)
}

// Classify labels a device based on its vendor and hostname. Port-aware
// identification (deep-scan results) refines this via ident.DeviceType.
func Classify(vendor, hostname string) string {
	return ident.DeviceType(vendor, hostname, "", nil)
}

// EnrichHostnames is the last-hurdle identification pass: hosts whose fast
// lookup (reverse DNS + single mDNS probe) found no name get asked all at once
// through the multicast group, then individually by NetBIOS status query — so
// Windows and quiet IoT devices that ignore DNS/mDNS still surface a name and
// a better device type. Everything is time-bounded and returns silently when
// a host simply has nothing to say.
func EnrichHostnames(ctx context.Context, rows []Row) {
	var need []string
	for i := range rows {
		if rows[i].Hostname == "" {
			need = append(need, rows[i].IP)
		}
	}
	if len(need) == 0 {
		return
	}
	names := ident.BrowseMDNS(ctx, need)
	for i := range rows {
		if rows[i].Hostname == "" && names[rows[i].IP] != "" {
			rows[i].Hostname = names[rows[i].IP]
		}
	}
	for i := range rows {
		if rows[i].Hostname != "" {
			continue
		}
		// Each NetBIOS query costs a round trip, and the loop is serial, so a
		// cancelled sweep would otherwise keep asking one host after another
		// long after the operator asked to stop.
		if ctx.Err() != nil {
			return
		}
		if n := ident.NetBIOSName(ctx, rows[i].IP); n != "" {
			rows[i].Hostname = n
		}
	}
	// A freshly found name may unlock a device-type hint that the initial
	// guess missed (only when no classification was made yet).
	for i := range rows {
		if rows[i].Type == "" && rows[i].Hostname != "" {
			rows[i].Type = ident.DeviceType(rows[i].Vendor, rows[i].Hostname, "", nil)
		}
	}
}

// EnrichServices fills each row's Services field with the mDNS/DNS-SD service
// labels (Avahi-style: airplay, ssh, chromecast, printer, …) its address
// advertises on the multicast channel. It is a garnish, not a dependency: it
// returns silently when disabled or when the network has no responders.
func EnrichServices(ctx context.Context, rows []Row, enabled bool) {
	if !enabled || len(rows) == 0 {
		return
	}
	ips := make([]string, 0, len(rows))
	for _, r := range rows {
		ips = append(ips, r.IP)
	}
	labels := ident.ServiceLabels(ctx, ips)
	for i := range rows {
		if l := labels[rows[i].IP]; len(l) > 0 {
			rows[i].Services = l
		}
	}
}
