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

package engine

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// Qdisc is a snapshot of the netem leaf in the shaping tree, read live from
// `tc -s qdisc show` while a test runs. It is the "see the hand" telemetry of
// GNULTE 15: the operator watches the impairment land on real packets.
type Qdisc struct {
	Found    bool  // a netem leaf was present in the qdisc dump
	Limit    int   // netem packet limit (1000 by default)
	DelayMs  int   // configured base delay, ms (the whole "delay a.b c.d" spec is not parsed)
	Delayed  int64 // packets the netem tree delayed (lifetime)
	Reordered int64 // packets re-ordered (lifetime)
	Dropped  int64 // packets dropped by the qdisc (lifetime)
	Backlog  int64 // packets waiting in the queue right now
}

// QdiscStats reads the current qdisc tree of the interface and parses the
// netem leaf GNULTE arms under parent 1:10. Showing a qdisc needs no
// privileges, so a non-root user sees the telemetry too; when tc is missing or
// no netem leaf exists, Found is false and the monitor simply omits the pane.
func QdiscStats(ctx context.Context, iface string) (Qdisc, error) {
	return parseQdiscStats(runTCShow(ctx, iface), iface), nil
}

// runTCShow captures `tc -s qdisc show dev IFACE`, returning "" on any error
// (command missing, context cancelled, tc failing).
func runTCShow(ctx context.Context, iface string) string {
	cmd := exec.CommandContext(ctx, "tc", "-s", "qdisc", "show", "dev", iface)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// parseQdiscStats scans a tc -s qdisc dump and pulls the netem block, which
// looks like:
//
//	qdisc netem 10: parent 1:10 limit 1000 delay 1500.0ms  300.0ms
//	 Sent 123456 bytes 789 pkt (dropped 34, overlimits 0 requeues 0)
//	 backlog 4321b 90p requeues 0
//	 rate 51200bit 8pps backlog 4321b 90p requeues 0
//	  delayed 456 packets
//	  reordered 12 packets
//	  fast 0 packets
//	  maybe_dropped 0 packets
//	  dropped 0 packets
//
// Only the fields the monitor displays are extracted; parsing is on purpose
// tolerant (any missing field simply stays zero).
func parseQdiscStats(out, iface string) Qdisc {
	q := Qdisc{}
	if strings.TrimSpace(out) == "" {
		return q
	}
	var block []string
	in := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "qdisc netem") {
			in = true
			block = []string{line}
			continue
		}
		if in {
			if strings.Contains(line, "qdisc ") && !strings.HasPrefix(strings.TrimSpace(line), "backlog") {
				break // next qdisc block starts
			}
			block = append(block, line)
		}
	}
	if len(block) == 0 {
		return q
	}
	q.Found = true

	head := block[0]
	q.Limit = int(numAfter(head, "limit"))
	if d, ok := floatAfter(head, "delay "); ok {
		q.DelayMs = int(d)
	}
	for _, line := range block[1:] {
		switch {
		case strings.Contains(line, " delayed "):
			q.Delayed = numAfter(line, "delayed")
		case strings.Contains(line, " reordered "):
			q.Reordered = numAfter(line, "reordered")
		case strings.Contains(line, "(dropped "):
			q.Dropped = numAfter(line, "(dropped")
		case strings.HasPrefix(strings.TrimSpace(line), "backlog"):
			q.Backlog = backlogPkts(line)
		}
	}
	if q.Dropped == 0 {
		// Some kernels report the drop counter on its own line.
		for _, line := range block[1:] {
			if strings.TrimSpace(line) == "dropped 0 packets" {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "dropped ") && strings.Contains(line, "packets") {
				q.Dropped = numAfter(line, "dropped")
			}
		}
	}
	return q
}

// backlogPkts reads the packet count from a backlog line like
// " backlog 4321b 90p requeues 0" (fields: backlog, <bytes>b, <pkts>p, ...).
func backlogPkts(line string) int64 {
	f := strings.Fields(line)
	var n int64
	for _, tok := range f {
		t := strings.TrimSuffix(strings.TrimSuffix(tok, "p"), "P")
		if t == tok {
			continue
		}
		v, err := strconv.ParseInt(t, 10, 64)
		if err == nil {
			n = v
		}
	}
	return n
}

// numAfter extracts the first integer after label (label not included).
func numAfter(s, label string) int64 {
	i := strings.Index(s, label)
	if i < 0 {
		return 0
	}
	rest := s[i+len(label):]
	f := firstNumber(rest)
	if f == "" {
		return 0
	}
	n, _ := strconv.ParseInt(f, 10, 64)
	return n
}

// floatAfter extracts the first number after label as a float (delay has a
// decimal part: "1500.0ms").
func floatAfter(s, label string) (float64, bool) {
	i := strings.Index(s, label)
	if i < 0 {
		return 0, false
	}
	rest := s[i+len(label):]
	f := firstNumber(rest)
	if f == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(f, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// firstNumber returns the leading integer/decimal run of s (minus signs not
// needed; tc counters are non-negative).
func firstNumber(s string) string {
	var b strings.Builder
	seenDot := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		if r == '.' && !seenDot {
			seenDot = true
			b.WriteRune(r)
			continue
		}
		if b.Len() > 0 {
			break
		}
	}
	return b.String()
}