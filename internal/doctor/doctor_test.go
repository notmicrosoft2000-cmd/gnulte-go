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

package doctor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// healthy is the all-clear fact set; individual tests knock out one condition at
// a time so a check's behaviour is isolated from the rest of the report.
func healthy() Facts {
	return Facts{
		EUID:            0,
		HasTC:           true,
		HasIPTables:     true,
		ForwardValue:    "0",
		NetemModule:     true,
		NetfilterModule: true,
		Iface:           "wlan0",
		SelfIP:          "192.168.99.132",
		Gateway:         "192.168.99.1",
		IfaceUp:         true,
		Neighbors:       7,
		Accepted:        true,
	}
}

// statusOf finds a check by name; every report must carry it.
func statusOf(t *testing.T, checks []Check, name string) Status {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c.Status
		}
	}
	t.Fatalf("no %q check in report %+v", name, checks)
	return Pass
}

func TestRunAllClear(t *testing.T) {
	checks := Run(healthy())
	if got := ExitCode(checks); got != 0 {
		t.Fatalf("ExitCode = %d, want 0 for a healthy machine: %+v", got, checks)
	}
	_, warn, fail := Counts(checks)
	if warn != 0 || fail != 0 {
		t.Fatalf("healthy machine reported warn=%d fail=%d: %+v", warn, fail, checks)
	}
	// The report should be non-trivial: every promised check must appear.
	for _, name := range []string{
		"privileges", "tc", "iptables", "ip_forward", "netem scheduler",
		"netfilter (iptables)", "default route", "interface up",
		"duplicate IPs", "safety acceptance",
	} {
		statusOf(t, checks, name)
	}
}

func TestMissingUtilitiesFailAndExitNonZero(t *testing.T) {
	f := healthy()
	f.HasTC = false
	f.HasIPTables = false
	checks := Run(f)
	if got := statusOf(t, checks, "tc"); got != Fail {
		t.Fatalf("missing tc = %v, want Fail", got)
	}
	if got := statusOf(t, checks, "iptables"); got != Fail {
		t.Fatalf("missing iptables = %v, want Fail", got)
	}
	if ExitCode(checks) == 0 {
		t.Fatal("a machine missing tc/iptables must exit non-zero")
	}
	// A failing check has to tell the operator how to fix it.
	for _, c := range checks {
		if c.Status == Fail && c.Hint == "" {
			t.Errorf("failing check %q has no hint", c.Name)
		}
	}
}

func TestNonRootWarnsButDoesNotFail(t *testing.T) {
	f := healthy()
	f.EUID = 1000
	checks := Run(f)
	if got := statusOf(t, checks, "privileges"); got != Warn {
		t.Fatalf("non-root privileges = %v, want Warn", got)
	}
	// The read-only tools work without root, so this must not block the run.
	if ExitCode(checks) != 0 {
		t.Fatal("non-root alone must not make the doctor fail")
	}
}

func TestChecksThatCanFail(t *testing.T) {
	base := healthy
	cases := []struct {
		name  string
		check string
		mut   func(*Facts)
	}{
		{"ip_forward unreadable", "ip_forward", func(f *Facts) {
			f.ForwardErr = errors.New("open /proc/sys/net/ipv4/ip_forward: no such file")
		}},
		{"no default route", "default route", func(f *Facts) {
			f.RouteErr = errors.New("no default route on this host")
		}},
		{"interface down", "interface up", func(f *Facts) {
			f.IfaceUp = false
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base()
			tc.mut(&f)
			checks := Run(f)
			if got := statusOf(t, checks, tc.check); got != Fail {
				t.Fatalf("%s = %v, want Fail", tc.check, got)
			}
			if ExitCode(checks) == 0 {
				t.Fatalf("%s should make the doctor exit non-zero", tc.check)
			}
		})
	}
}

func TestChecksThatWarn(t *testing.T) {
	base := healthy
	cases := []struct {
		name  string
		check string
		mut   func(*Facts)
	}{
		{"netem module missing", "netem scheduler", func(f *Facts) { f.NetemModule = false }},
		{"netfilter module missing", "netfilter (iptables)", func(f *Facts) { f.NetfilterModule = false }},
		{"empty ARP table", "duplicate IPs", func(f *Facts) { f.Neighbors = 0 }},
		{"duplicate addresses", "duplicate IPs", func(f *Facts) { f.DupConflicts = 3 }},
		{"safety not accepted", "safety acceptance", func(f *Facts) { f.Accepted = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base()
			tc.mut(&f)
			checks := Run(f)
			if got := statusOf(t, checks, tc.check); got != Warn {
				t.Fatalf("%s = %v, want Warn", tc.check, got)
			}
			if ExitCode(checks) != 0 {
				t.Fatalf("%s is a warning and must not change the exit code", tc.check)
			}
		})
	}
}

// TestDuplicateConflictBeatsEmptyTable: a populated table with a conflict is the
// conflict warning, not the empty-table one — the two share a check name.
func TestDuplicateConflictBeatsEmptyTable(t *testing.T) {
	f := healthy()
	f.Neighbors = 5
	f.DupConflicts = 2
	checks := Run(f)
	var detail string
	for _, c := range checks {
		if c.Name == "duplicate IPs" {
			detail = c.Detail
		}
	}
	if !strings.Contains(detail, "share a MAC") {
		t.Fatalf("duplicate detail = %q, want the conflict wording", detail)
	}
}

func TestExitCodeOnlyLooksAtFailures(t *testing.T) {
	if ExitCode([]Check{{Name: "a", Status: Pass}, {Name: "b", Status: Warn}}) != 0 {
		t.Fatal("pass+warn must exit 0")
	}
	if ExitCode([]Check{{Name: "a", Status: Pass}, {Name: "b", Status: Fail}}) != 1 {
		t.Fatal("any failure must exit 1")
	}
}

// TestCheckJSONUsesWords guards the --json contract: a script reads "status" as
// PASS/WARN/FAIL, not the internal enum number.
func TestCheckJSONUsesWords(t *testing.T) {
	raw, err := json.Marshal([]Check{{Name: "tc", Status: Fail, Detail: "not found", Hint: "apt install iproute2"}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(raw)
	for _, want := range []string{`"check":"tc"`, `"status":"FAIL"`, `"detail":"not found"`, `"hint":"apt install iproute2"`} {
		if !strings.Contains(got, want) {
			t.Errorf("json = %s, missing %s", got, want)
		}
	}
	if strings.Contains(got, `"status":`) && strings.Contains(got, `:2`) {
		t.Errorf("json leaked the enum value: %s", got)
	}
}
