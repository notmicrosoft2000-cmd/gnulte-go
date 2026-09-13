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

// Package scanner runs deep scans entirely in Go: TCP connects across the
// commonly open ports, service identification from the port number, banner
// grabbing for protocols that announce themselves, and an operating-system
// guess from the ICMP TTL. It replaces the former delegation to the `nmap`
// child process, so the deep scan needs no external tool and reports the same
// information a LAN scan usually wants — open ports, services, banners, and an
// OS estimate per host.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"gnulte-go/internal/probe"
)

// Port is one open TCP port with the service name it maps to and any banner
// the daemon revealed.
type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// Result of a deep scan of one host.
type Result struct {
	Ports []Port `json:"ports"`
	OS    string `json:"os,omitempty"`
	TTL   int    `json:"ttl"`
	Note  string `json:"note,omitempty"`
}

// dialTimeout bounds each TCP connect and banner read.
const dialTimeout = 600 * time.Millisecond

// scanPorts is the curated list of ports probed during a deep scan. It covers
// the mix a home/office LAN actually exposes (web, mail, file sharing, remote
// management, databases, IOT) without taking a minute per host.
var scanPorts = []int{
	21, 22, 23, 25, 26, 37, 53, 69, 80, 81, 88, 110, 111, 113, 119, 123,
	135, 137, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 514,
	515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1025, 1080, 1234,
	1433, 1521, 1723, 1883, 1900, 2000, 2049, 2082, 2083, 2222, 2375,
	2376, 2483, 2484, 3000, 3128, 3268, 3306, 3389, 3478, 3690, 4369,
	5000, 5001, 5060, 5061, 5222, 5228, 5353, 5432, 5555, 5601, 5672,
	5900, 5985, 5986, 6379, 6443, 6881, 7001, 8000, 8008, 8080, 8081,
	8086, 8087, 8181, 8200, 8443, 8500, 8880, 8888, 9000, 9001, 9090,
	9092, 9100, 9200, 9418, 10000, 11211, 15672, 20000, 27017, 27018,
}

// services maps well-known ports to their human service names.
var services = func() map[int]string {
	m := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 26: "smtp",
		37: "time", 53: "domain", 69: "tftp", 80: "http", 81: "http",
		88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident",
		119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
		139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
		179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "microsoft-ds",
		465: "smtps", 500: "isakmp", 514: "syslog", 515: "lpd", 548: "afp",
		554: "rtsp", 587: "smtp", 631: "ipp", 636: "ldaps", 873: "rsync",
		902: "vmware", 993: "imaps", 995: "pop3s", 1025: "nfs-or-rpc",
		1080: "socks", 1234: "vlc-http", 1433: "mssql", 1521: "oracle",
		1723: "pptp", 1883: "mqtt", 1900: "upnp", 2000: "cisco-sccp",
		2049: "nfs", 2082: "cpanel-http", 2083: "cpanel-https", 2222: "ssh",
		2375: "docker", 2376: "docker-tls", 2483: "oracle", 2484: "oracle-tls",
		3000: "http-dev", 3128: "squid", 3268: "ad-global-catalog",
		3306: "mysql", 3389: "ms-wbt-server", 3478: "stun", 3690: "svn",
		4369: "erlang", 5000: "upnp-http", 5001: "stun", 5060: "sip",
		5061: "sips", 5222: "xmpp", 5228: "gcm", 5353: "mdns", 5432: "postgresql",
		5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm",
		5986: "winrm-https", 6379: "redis", 6443: "kubernetes-api",
		6881: "bittorrent", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
		8080: "http-proxy", 8081: "http-alt", 8086: "influxdb", 8087: "http-alt",
		8181: "http-alt", 8200: "http-alt", 8443: "https-alt", 8500: "consul",
		8880: "http-alt", 8888: "http-alt", 9000: "http-alt", 9001: "http-alt",
		9090: "prometheus", 9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
		9418: "git", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
		20000: "usermin", 27017: "mongodb", 27018: "mongodb-shard",
	}
	return m
}()

// tlsPorts are services whose greeting is encrypted and useless as a banner.
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 993: true, 995: true, 2083: true,
	2376: true, 2484: true, 5061: true, 5986: true, 8443: true,
}

const scanConcurrency = 96

// DeepScan probes the scan ports of ip in parallel. A port responds to a TCP
// connect either by accepting (open) or refusing (closed); an ICMP ping also
// feeds the TTL used for the OS guess. The result lists every open port with
// its service and banner, plus the OS estimate.
func DeepScan(ctx context.Context, ip string) Result {
	var res Result
	ttl := osTTL(ctx, ip)
	res.TTL = ttl
	res.OS = guessOS(ttl)

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	sem := make(chan struct{}, scanConcurrency)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		opens []Port
	)
	for _, p := range scanPorts {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			if portOpen(ctx, ip, port) {
				b := bannerFor(ctx, ip, port)
				mu.Lock()
				opens = append(opens, Port{Port: port, Service: services[port], Banner: b})
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	if len(opens) == 0 {
		res.Note = "no open ports in the common range"
	}
	if ttl == 0 {
		res.Note = trimJoin(res.Note, "icmp filtered; OS guess unavailable", " · ")
	}
	res.Ports = sortPorts(opens)
	return res
}

// sortPorts orders the open ports ascending.
func sortPorts(ps []Port) []Port {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && ps[j].Port < ps[j-1].Port; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
	return ps
}

func trimJoin(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "")
}

// osTTL asks the system ping for the reply TTL (0 = silent host).
func osTTL(ctx context.Context, ip string) int {
	_, ttl := pingContext(ctx, ip)
	return ttl
}

// pingContext isolates the ping call so tests can inject a stub without
// exercising the real stack.
var pingContext = func(ctx context.Context, ip string) (rtt int, ttl int) {
	c, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()
	return probe.Ping(c, ip, 900*time.Millisecond)
}

// portOpen reports whether a TCP connect completes within the window.
func portOpen(ctx context.Context, ip string, port int) bool {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// bannerFor reads a greeting (or sends one polite probe) and returns the
// daemon's banner, sanitized to a single short line. TLS ports are skipped —
// their greeting is the encrypted ServerHello, useless as text.
func bannerFor(ctx context.Context, ip string, port int) string {
	if tlsPorts[port] {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))

	if isWebPort(port) {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	} else if port == 110 || port == 995 {
		// POP3: banner is the greeting; nothing to write.
	} else if port == 21 || port == 1433 || port == 4369 || port == 5432 ||
		port == 3306 || port == 27017 || port == 27018 || port == 5672 {
		// These daemons announce themselves on connect; read only.
	}

	var buf bytes.Buffer
	tmp := make([]byte, 256)
	for {
		n, err := conn.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil || buf.Len() >= 512 {
			break
		}
	}

	banner := firstLine(buf.String())
	if isWebPort(port) {
		// Prefer the Server: header over the raw request echo.
		if s := webServer(buf.String()); s != "" {
			banner = s
		}
	}
	return sanitize(banner)
}

// isWebPort lists HTTP listeners that need a request before they speak.
func isWebPort(port int) bool {
	switch port {
	case 80, 81, 3000, 3128, 5000, 8000, 8008, 8080, 8081, 8086, 8087,
		8181, 8200, 8500, 8880, 8888, 9000, 9001, 9090, 9200, 9418,
		10000, 20000, 15672:
		return true
	}
	return false
}

// webServer extracts the Server header from an HTTP reply.
func webServer(raw string) string {
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(strings.ToLower(l), "server:") {
			return strings.TrimSpace(l[len("server:"):])
		}
	}
	return ""
}

// firstLine keeps only the first non-empty line of a raw reply, before any
// control-byte collapsing, so daemon greetings like "SSH-2.0-dropbear…" and
// "220 FTP ready" stay clean even when KEX or binary data follows.
func firstLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "\n")
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			return l
		}
	}
	return ""
}

// sanitize reduces a raw reply to printable single-line text: control bytes
// (including CR/LF and NUL) become spaces, runs collapse, and long banners get
// truncated so they fit a table and a report cleanly.
func sanitize(s string) string {
	var b strings.Builder
	var prevSpace bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteByte(c)
		prevSpace = false
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// guessOS infers an operating system family from the ICMP reply TTL, which
// starts at a well-known value and only decreases with hops.
func guessOS(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Network device"
	}
	return ""
}
