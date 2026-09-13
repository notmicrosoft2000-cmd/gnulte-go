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

var vendorCache sync.Map // prefix -> vendor, loaded lazily

// VendorFor maps a MAC (upper hex, any separator) to a vendor name. It loads
// an OUI file if one exists, otherwise uses the built-in minimal database.
func VendorFor(mac string) string {
	if mac == "" {
		return ""
	}
	prefix := strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", "")
	if len(prefix) < 6 {
		return ""
	}
	prefix = strings.ToUpper(prefix[:6])
	if v, ok := vendorCache.Load(prefix); ok {
		return v.(string)
	}
	v := loadVendors()[prefix]
	vendorCache.Store(prefix, v)
	return v
}

func loadVendors() map[string]string {
	db := map[string]string{}
	for _, p := range []string{
		os.Getenv("XDG_CONFIG_HOME") + "/gnulte-go/oui.txt",
		os.Getenv("HOME") + "/.config/gnulte-go/oui.txt",
		"/usr/share/gnulte/oui.txt",
		"/usr/share/gnulte-go/oui.txt",
	} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			// Format: "00-00-00   (hex)		Apple, Inc." or "000000 (base 16) ..."
			hexPart := line
			if idx := strings.Index(line, "(hex)"); idx >= 0 {
				hexPart = strings.TrimSpace(line[:idx])
			} else if idx := strings.Index(line, "(base 16)"); idx >= 0 {
				hexPart = strings.TrimSpace(line[:idx])
			}
			hex := strings.ReplaceAll(hexPart, "-", "")
			if len(hex) != 6 {
				continue
			}
			rest := strings.TrimSpace(line[strings.Index(line, ")")+1:])
			if rest != "" {
				db[hex] = rest
			}
		}
		if len(db) > 0 {
			break
		}
	}
	builtins := map[string]string{
		"000C29": "VMware", "005056": "VMware", "000569": "VMware",
		"080027": "Oracle VirtualBox", "00155D": "Microsoft Hyper-V",
		"525400": "QEMU/KVM", "F8B156": "ASUSTek/Raspberry Pi?",
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
		"D8F1F5": "Raspberry Pi", "28CDC1": "Raspberry Pi", "C2FF5E": "Raspberry Pi",
		"DC46A6": "TP-LINK", "508A06": "TP-LINK", "FCB4E6": "TP-LINK",
	}
	for k, v := range builtins {
		db[k] = v
	}
	return db
}

// ResolveHost does reverse DNS, bounded so a LAN without a reverse zone
// cannot stall the scan (falls back gracefully).
func ResolveHost(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	r, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(r) == 0 {
		return ""
	}
	return strings.TrimSuffix(r[0], ".")
}

// Classify labels a device based on its vendor and hostname.
func Classify(vendor, hostname string) string {
	v := strings.ToLower(vendor)
	n := strings.ToLower(hostname)
	switch {
	case strings.Contains(v, "apple") || strings.Contains(n, "ipad") || strings.Contains(n, "iphone"):
		return "Apple device"
	case strings.Contains(v, "samsung") || strings.Contains(v, "xiaomi") ||
		strings.Contains(n, "android") || strings.Contains(n, "phone"):
		return "Mobile"
	case strings.Contains(v, "tp-link") || strings.Contains(v, "asus") ||
		strings.Contains(v, "netgear") || strings.Contains(v, "linksys") ||
		strings.Contains(v, "d-link") || strings.Contains(v, "huawei"):
		return "Router/AP"
	case strings.Contains(v, "raspberry"):
		return "Raspberry Pi"
	case strings.Contains(v, "microsoft") || strings.Contains(v, "intel") ||
		strings.Contains(v, "dell") || strings.Contains(v, "lenovo") ||
		strings.Contains(v, "hp "):
		return "Computer"
	case strings.Contains(v, "sony") || strings.Contains(v, "lg") ||
		strings.Contains(v, "samsung") || strings.Contains(v, "chromecast") ||
		strings.Contains(n, "tv"):
		return "Media/IoT"
	default:
		if vendor != "" {
			return "Device"
		}
		return ""
	}
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
