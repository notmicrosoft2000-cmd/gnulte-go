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
// system `ping`, neighbor resolution from /proc/net/arp (optionally boosted by
// `arp-scan` when running as root), vendor identification, and hostname
// resolution. `-d/--deep` additionally runs the in-Go port scanner against
// alive hosts.
package discover

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gnulte-go/internal/ident"
	"gnulte-go/internal/scanner"
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
	Banners  []string
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

// Neighbors returns ip->MAC from /proc/net/arp, optionally restricted to one
// interface (empty = all). If arp-scan is available and we are root it is used
// first to also learn quiet devices.
func Neighbors(ctx context.Context, iface string) map[string]string {
	out := map[string]string{}
	// Opportunistic arp-scan: only as root and only when the tool exists.
	if os.Geteuid() == 0 {
		if path, err := exec.LookPath("arp-scan"); err == nil {
			cmd := exec.CommandContext(ctx, path, "--interface="+iface, "--localnet", "--retry=2")
			if raw, err := cmd.Output(); err == nil {
				for _, line := range strings.Split(string(raw), "\n") {
					f := strings.Fields(line)
					if len(f) >= 2 && net.ParseIP(f[0]) != nil && isMAC(f[1]) {
						out[f[0]] = strings.ToUpper(f[1])
					}
				}
			}
		}
	}
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

func isMAC(s string) bool {
	if len(s) < 17 {
		return false
	}
	for _, b := range s {
		if strings.ContainsRune("0123456789abcdefABCDEF:-", b) == false && b != '.' {
			return false
		}
	}
	return strings.Count(s, ":") == 5 || strings.Count(s, "-") == 5
}

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

// DeepScan runs the in-Go port scanner against one IP. The port list, TTL-based
// OS guess, service banners, and any scan note replace what the old nmap
// delegation produced — so the deep scan works with no external tool. Errors
// come back as a human note instead of aborting the whole scan.
func DeepScan(ctx context.Context, ip string) (ports, osName string, banners []string, note string) {
	res := scanner.DeepScan(ctx, ip)
	if len(res.Ports) == 0 {
		ports = "(no open ports in common range)"
	} else {
		parts := make([]string, 0, len(res.Ports))
		for _, p := range res.Ports {
			s := fmt.Sprintf("%d/open/tcp", p.Port)
			if p.Service != "" {
				s += "/" + p.Service
			}
			parts = append(parts, s)
		}
		ports = strings.Join(parts, ", ")
		hostNames := make([]string, 0, len(res.Ports))
		for _, p := range res.Ports {
			name := fmt.Sprintf("%d (%s)", p.Port, serviceOrNumber(p))
			if p.Banner != "" {
				name += ": " + p.Banner
				hostNames = append(hostNames, name)
			}
		}
		banners = hostNames
	}
	osName = res.OS
	note = res.Note
	return ports, osName, banners, note
}

// serviceOrNumber names a port by its well-known service, falling back to the
// bare port number, so banner lines stay readable.
func serviceOrNumber(p scanner.Port) string {
	if p.Service != "" {
		return p.Service
	}
	return strconv.Itoa(p.Port)
}
