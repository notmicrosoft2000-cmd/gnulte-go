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

// Package probe checks whether a target is reachable without depending on a
// single protocol. Many hosts — and many admins — block ICMP echo, so a ping
// timeout alone is a poor "is the internet working?" signal. probe falls back
// to TCP connects (SYN/ACK = port open, RST = host alive but port closed) and
// reports both the latency and the mechanism that answered.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DefaultPorts are probed when the caller supplies none: common service ports
// that firewalls tend to leave open for the LAN's own use.
var DefaultPorts = []int{443, 80, 53}

// tcpDialTimeout bounds each TCP connect probe. A host that cannot answer
// within this window is treated as unreachable regardless of ICMP policy.
const tcpDialTimeout = 1200 * time.Millisecond

// PortState describes the outcome of a TCP connect probe.
type PortState string

const (
	// Open means the host completed a TCP handshake (SYN/ACK).
	Open PortState = "open"
	// Refused means the host answered with RST: it is alive, the port is not
	// listening.
	Refused PortState = "refused"
	// Timeout means no reply at all came back within the window.
	Timeout PortState = "timeout"
	// Unreachable means a router returned a hard no-route error.
	Unreachable PortState = "unreachable"
)

// PortResult is one TCP probe against a single port.
type PortResult struct {
	Port  int
	State PortState
	RTTMs int
}

// Result is the combined reachability verdict across ICMP and TCP.
type Result struct {
	ICMP    bool
	ICMPMs  int
	ICMPTTL int
	TCP     []PortResult
}

// Alive reports whether the target answered on any probed channel. A refused
// TCP port still proves the host is there — only complete silence means down.
func (r Result) Alive() bool {
	if r.ICMP {
		return true
	}
	for _, p := range r.TCP {
		if p.State == Open || p.State == Refused {
			return true
		}
	}
	return false
}

// Latency returns the best measurable round-trip time across all channels
// (ICMP first, then the fastest TCP reply), or -1 when the target is silent.
func (r Result) Latency() int {
	if r.ICMP {
		return r.ICMPMs
	}
	best := -1
	for _, p := range r.TCP {
		if (p.State == Open || p.State == Refused) && (best < 0 || p.RTTMs < best) {
			best = p.RTTMs
		}
	}
	return best
}

// Method names the mechanism that confirmed the host was alive.
func (r Result) Method() string {
	switch {
	case r.ICMP:
		return "icmp"
	case len(r.TCP) > 0 && r.TCP[0].State == Open:
		return "tcp"
	case len(r.TCP) > 0 && r.TCP[0].State == Refused:
		return "tcp-refused"
	case len(r.TCP) > 0 && r.TCP[0].State == Unreachable:
		return "unreachable"
	default:
		return "silent"
	}
}

// Note is a compact human-readable verdict for the live console, e.g.
// "icmp 12ms", "tcp:443 4ms", "tcp:80/refused 1ms".
func (r Result) Note() string {
	switch {
	case r.ICMP:
		return fmt.Sprintf("icmp %dms", r.ICMPMs)
	case len(r.TCP) == 0:
		return "no answer"
	case r.TCP[0].State == Open:
		return fmt.Sprintf("tcp:%d %dms", r.TCP[0].Port, r.TCP[0].RTTMs)
	case r.TCP[0].State == Refused:
		return fmt.Sprintf("tcp:%d/refused %dms", r.TCP[0].Port, r.TCP[0].RTTMs)
	default:
		return string(r.TCP[0].State)
	}
}

// Ping performs a single ICMP echo via the system ping and returns the RTT
// (or -1 on no reply) and the reply TTL.
func Ping(ctx context.Context, ip string, timeout time.Duration) (rtt int, ttl int) {
	if timeout <= 0 {
		timeout = time.Second
	}
	secs := int((timeout + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(secs), "-n", ip).Output()
	if err != nil {
		return -1, 0
	}
	s := string(out)
	if i := strings.Index(s, "ttl="); i >= 0 {
		j := i + 4
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		ttl, _ = strconv.Atoi(s[i+4 : j])
	}
	i := strings.Index(s, "time=")
	if i < 0 || i+5 > len(s) {
		return -1, ttl
	}
	rest := s[i+5:]
	j := strings.IndexAny(rest, " \n\t")
	if j < 0 {
		j = len(rest)
	}
	rtt, _ = strconv.Atoi(rest[:j])
	return rtt, ttl
}

// Probe measures reachability to ip. ICMP echo is tried first (the classic
// metric); if it is silent the probe falls back to TCP connects against ports
// (DefaultPorts when none given) so a host that blocks ICMP is still counted
// as alive when its TCP stack answers.
func Probe(ctx context.Context, ip string, ports []int) Result {
	if rtt, ttl := tryPing(ctx, ip); rtt >= 0 {
		return Result{ICMP: true, ICMPMs: rtt, ICMPTTL: ttl}
	}
	return ProbeTCP(ctx, ip, ports)
}

// ProbeTCP measures reachability using TCP connects only — the caller already
// determined ICMP produced no answer and wants the fallback verdict.
func ProbeTCP(ctx context.Context, ip string, ports []int) Result {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	dialCtx, cancel := context.WithTimeout(ctx, tcpDialTimeout)
	defer cancel()
	var res Result
	for _, port := range ports {
		state, ms, done := dialPort(dialCtx, ip, port)
		res.TCP = append(res.TCP, PortResult{Port: port, State: state, RTTMs: ms})
		if done {
			return res
		}
	}
	return res
}

// tryPing wraps Ping with a short window; the standalone Probe path wants a
// quick confirm, not a long adaptive wait.
func tryPing(ctx context.Context, ip string) (int, int) {
	ctx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()
	return Ping(ctx, ip, 900*time.Millisecond)
}

func dialPort(ctx context.Context, ip string, port int) (PortState, int, bool) {
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: tcpDialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	ms := int(time.Since(start) / time.Millisecond)
	if err == nil {
		conn.Close()
		return Open, ms, true
	}
	var ne *net.OpError
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout, ms, false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return Timeout, ms, false
	}
	if strings.Contains(err.Error(), "connection refused") {
		return Refused, ms, true
	}
	return Unreachable, ms, false
}
