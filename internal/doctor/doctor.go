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

// Package doctor is the pre-flight health check behind gnulte-doctor. Gathering
// the facts about a machine is separated from judging them, so the check
// registry can be tested against any combination of conditions — including the
// ones this sandbox cannot create (root, a missing binary, a broken route).
package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/netutil"
	"gnulte-go/internal/safety"
)

// Status is the outcome of a single check.
type Status int

const (
	// Pass means the requirement is satisfied.
	Pass Status = iota
	// Warn means it is not ideal, or cannot be determined here, but the toolkit
	// can still run.
	Warn
	// Fail means the toolkit's core function is blocked until it is fixed.
	Fail
)

// String renders the status as the word shown in the report and JSON.
func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	}
	return "UNKNOWN"
}

// Check is one row of the report.
type Check struct {
	Name   string `json:"check"`
	Status Status `json:"-"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

// MarshalJSON reports the status as a word ("PASS"/"WARN"/"FAIL") rather than an
// opaque number.
func (c Check) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name   string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail,omitempty"`
		Hint   string `json:"hint,omitempty"`
	}{c.Name, c.Status.String(), c.Detail, c.Hint})
}

// Facts is everything the checks need. Gather fills it from the machine; tests
// fill it by hand, so every branch of Run is reachable without root.
type Facts struct {
	EUID            int
	HasTC           bool
	HasIPTables     bool
	ForwardValue    string // "" when unreadable
	ForwardErr      error
	NetemModule     bool
	NetfilterModule bool
	Iface           string
	SelfIP          string
	Gateway         string
	RouteErr        error
	IfaceUp         bool
	Neighbors       int
	DupConflicts    int
	Accepted        bool
	AcceptErr       error
}

// Gather reads the machine's state. The duplicate scan reuses the discovery
// path (cheap kernel read; a real ARP sweep only when root), so it can take a
// couple of seconds on a privileged run.
func Gather(ctx context.Context) Facts {
	f := Facts{EUID: os.Geteuid()}
	_, err := exec.LookPath("tc")
	f.HasTC = err == nil
	_, err = exec.LookPath("iptables")
	f.HasIPTables = err == nil

	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil {
		f.ForwardErr = err
	} else {
		f.ForwardValue = strings.TrimSpace(string(b))
	}

	mods := moduleSet()
	f.NetemModule = mods["sch_netem"]
	f.NetfilterModule = mods["ip_tables"] || mods["nf_tables"] || mods["iptable_filter"]

	if cfg, err := netutil.DefaultRoute(); err != nil {
		f.RouteErr = err
	} else {
		f.Iface, f.SelfIP, f.Gateway = cfg.Interface, cfg.SelfIP, cfg.Gateway
		if ifi, err := net.InterfaceByName(cfg.Interface); err == nil {
			f.IfaceUp = ifi.Flags&net.FlagUp != 0
		}
	}

	if ok, err := safety.Valid(safety.RecordPath()); err != nil {
		f.AcceptErr = err
	} else {
		f.Accepted = ok
	}

	f.Neighbors, f.DupConflicts = duplicateConflicts(ctx, f.Iface)
	return f
}

// duplicateConflicts counts ARP neighbours and how many addresses share a MAC.
// An empty table is not an error: it just means the LAN has not been prodded.
func duplicateConflicts(ctx context.Context, iface string) (neighbors, conflicts int) {
	if iface == "" {
		return 0, 0
	}
	found := discover.DiscoverNeighbors(ctx, iface)
	byMAC := map[string]int{}
	for _, mac := range found {
		if mac != "" {
			byMAC[mac]++
		}
	}
	for _, n := range byMAC {
		if n > 1 {
			conflicts += n
		}
	}
	return len(found), conflicts
}

// moduleSet reads loaded module names from /proc/modules. A module built into
// the kernel has no entry here, so a miss is a warning, never a failure.
func moduleSet() map[string]bool {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil
	}
	defer f.Close()
	set := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		name := line
		if i := strings.IndexByte(line, ' '); i > 0 {
			name = line[:i]
		}
		if name != "" {
			set[name] = true
		}
	}
	return set
}

// Run turns facts into the ordered list of checks. It is pure: the same facts
// always produce the same report, which is what makes it testable.
func Run(f Facts) []Check {
	var checks []Check

	if f.EUID == 0 {
		checks = append(checks, Check{"privileges", Pass, "running as root", ""})
	} else {
		checks = append(checks, Check{"privileges", Warn,
			fmt.Sprintf("euid %d — not root", f.EUID),
			"gnulte, gnulte-scan --arp, gnulte-wifi and traffic shaping need sudo; the read-only tools do not"})
	}

	checks = append(checks, toolCheck("tc", f.HasTC,
		"impair and shape traffic",
		"install iproute2 (Debian/Ubuntu: apt install iproute2; Fedora: dnf install iproute)"))
	checks = append(checks, toolCheck("iptables", f.HasIPTables,
		"block mode (FORWARD DROP)",
		"install iptables (Debian/Ubuntu: apt install iptables)"))

	if f.ForwardErr != nil {
		checks = append(checks, Check{"ip_forward", Fail, f.ForwardErr.Error(),
			"not Linux, or /proc is unavailable; the engine toggles ip_forward during a test"})
	} else {
		checks = append(checks, Check{"ip_forward", Pass, "ip_forward=" + f.ForwardValue, ""})
	}

	checks = append(checks, moduleCheck("netem scheduler", f.NetemModule,
		"modprobe sch_netem (or use a kernel with netem built in)"))
	checks = append(checks, moduleCheck("netfilter (iptables)", f.NetfilterModule,
		"modprobe ip_tables or nf_tables (or use a kernel with them built in)"))

	if f.RouteErr != nil {
		checks = append(checks, Check{"default route", Fail, f.RouteErr.Error(),
			"connect to a network, or pass -i INTERFACE to the tools"})
	} else {
		checks = append(checks, Check{"default route", Pass,
			fmt.Sprintf("%s via %s on %s", f.SelfIP, f.Gateway, f.Iface), ""})
		if f.Iface != "" && !f.IfaceUp {
			checks = append(checks, Check{"interface up", Fail, f.Iface + " is down",
				"ip link set " + f.Iface + " up"})
		} else if f.Iface != "" {
			checks = append(checks, Check{"interface up", Pass, f.Iface, ""})
		}
	}

	switch {
	case f.Neighbors == 0:
		checks = append(checks, Check{"duplicate IPs", Warn, "ARP table is empty",
			"ping the LAN first, or run as root for the ARP sweep"})
	case f.DupConflicts > 0:
		checks = append(checks, Check{"duplicate IPs", Warn,
			fmt.Sprintf("%d address(es) share a MAC", f.DupConflicts),
			"investigate before trusting the network (gnulte --dupcheck)"})
	default:
		checks = append(checks, Check{"duplicate IPs", Pass, "none detected", ""})
	}

	switch {
	case f.AcceptErr != nil:
		checks = append(checks, Check{"safety acceptance", Warn, f.AcceptErr.Error(),
			"run any GNULTE tool once to review and accept the safety notices"})
	case f.Accepted:
		checks = append(checks, Check{"safety acceptance", Pass, "on record", ""})
	default:
		checks = append(checks, Check{"safety acceptance", Warn, "not accepted yet",
			"run any GNULTE tool once to review and accept the safety notices"})
	}

	return checks
}

func toolCheck(name string, present bool, purpose, hint string) Check {
	if present {
		return Check{name, Pass, purpose, ""}
	}
	return Check{name, Fail, "not found in PATH", hint}
}

func moduleCheck(name string, present bool, hint string) Check {
	if present {
		return Check{name, Pass, "loaded", ""}
	}
	return Check{name, Warn, "not listed in /proc/modules (may be built in)", hint}
}

// ExitCode is non-zero when any check failed, so a script can gate on the doctor.
func ExitCode(checks []Check) int {
	for _, c := range checks {
		if c.Status == Fail {
			return 1
		}
	}
	return 0
}

// Counts returns the pass/warn/fail totals for the summary line.
func Counts(checks []Check) (pass, warn, fail int) {
	for _, c := range checks {
		switch c.Status {
		case Pass:
			pass++
		case Warn:
			warn++
		case Fail:
			fail++
		}
	}
	return pass, warn, fail
}
