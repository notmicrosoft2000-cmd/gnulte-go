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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gnulte-go/internal/icmp"
	"gnulte-go/internal/trace"
	"gnulte-go/internal/tui"
)

// sample is a small finished trace reused by the rendering tests.
func sample() trace.Result {
	return trace.Result{
		Target:  "203.0.113.5",
		Reached: true,
		Hops: []trace.Hop{
			{TTL: 1, Addr: "10.0.0.1", RTTs: []int{5, 7}, Kind: icmp.HopReply},
			{TTL: 2, Addr: "203.0.113.5", RTTs: []int{20, 22}, Kind: icmp.TargetReply},
		},
	}
}

func TestMSFormatting(t *testing.T) {
	cases := map[int]string{-1: "*", 0: "0ms", 42: "42ms"}
	for in, want := range cases {
		if got := ms(in); got != want {
			t.Errorf("ms(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestHopRow(t *testing.T) {
	row := hopRow(trace.Hop{TTL: 1, Addr: "10.0.0.1", RTTs: []int{5, 7}})
	for _, want := range []string{"10.0.0.1", "5ms", "6ms", "7ms", "0%"} {
		if !strings.Contains(row, want) {
			t.Errorf("hopRow missing %q: %q", want, row)
		}
	}
	// A hop where every probe was lost shows the placeholder and full loss.
	lost := hopRow(trace.Hop{TTL: 4, RTTs: []int{-1, -1}})
	if !strings.Contains(lost, "*") {
		t.Errorf("lost hop should use the * placeholder: %q", lost)
	}
	if !strings.Contains(lost, "100%") {
		t.Errorf("lost hop should report 100%% loss: %q", lost)
	}
}

func TestSummaryStates(t *testing.T) {
	var b bytes.Buffer
	printSummary(&b, sample(), time.Now().Add(-time.Second))
	if !strings.Contains(b.String(), "REACHED") || !strings.Contains(b.String(), "203.0.113.5") {
		t.Fatalf("reached summary = %q", b.String())
	}

	b.Reset()
	printSummary(&b, trace.Result{Target: "203.0.113.9", Unreachable: true, Hops: sample().Hops}, time.Now())
	if !strings.Contains(b.String(), "UNREACHABLE") {
		t.Fatalf("unreachable summary = %q", b.String())
	}

	b.Reset()
	printSummary(&b, trace.Result{Target: "203.0.113.9", Hops: sample().Hops}, time.Now())
	if !strings.Contains(b.String(), "no answer") {
		t.Fatalf("incomplete summary = %q", b.String())
	}
}

func TestEmitJSONContract(t *testing.T) {
	var b bytes.Buffer
	emitJSON(&b, sample(), trace.Options{Probes: 3, MaxHops: 30}, time.Now())

	var got jsonResult
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, b.String())
	}
	if got.Target != "203.0.113.5" || !got.Reached {
		t.Fatalf("result = %+v, want the sample target reached", got)
	}
	if len(got.Hops) != 2 {
		t.Fatalf("got %d hops, want 2", len(got.Hops))
	}
	if got.Hops[0].Addr != "10.0.0.1" || got.Hops[0].Kind != "hop" {
		t.Fatalf("hop 1 = %+v", got.Hops[0])
	}
	if got.Hops[1].Kind != "reply" || got.Hops[1].Avg != 21 {
		t.Fatalf("hop 2 = %+v, want kind reply and avg 21ms", got.Hops[1])
	}
}

func TestWriteHTMLReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.html")
	if err := writeHTML(path, sample(), trace.Options{Probes: 3, MaxHops: 30}, time.Now()); err != nil {
		t.Fatalf("writeHTML: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	html := string(raw)
	for _, want := range []string{"<!doctype html>", "203.0.113.5", "10.0.0.1", "<table>", "reached"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestResolveTarget(t *testing.T) {
	if got, err := resolveTarget("192.168.1.5"); err != nil || got != "192.168.1.5" {
		t.Fatalf("resolveTarget(IPv4) = %q, %v", got, err)
	}
	if _, err := resolveTarget("::1"); err == nil {
		t.Fatal("IPv6 should be refused with a clear error")
	}
}

func TestIsQuitKey(t *testing.T) {
	for _, tc := range []struct {
		k tui.Key
		r rune
	}{
		{tui.KeyEsc, 0}, {tui.KeyEnter, 0}, {tui.KeyRune, 'q'}, {tui.KeyRune, 'Q'},
	} {
		if !isQuitKey(tc.k, tc.r) {
			t.Errorf("isQuitKey(%v,%q) = false, want true", tc.k, tc.r)
		}
	}
	if isQuitKey(tui.KeyRune, 'x') {
		t.Error("isQuitKey('x') = true, want false")
	}
}

func TestPrivilegeHintNamesRoot(t *testing.T) {
	got := privilegeHint(syscall.EPERM)
	if !strings.Contains(got.Error(), "root") {
		t.Fatalf("privilegeHint(EPERM) = %v, want a root hint", got)
	}
	plain := os.ErrNotExist
	if privilegeHint(plain) != plain {
		t.Fatalf("privilegeHint must pass unrelated errors through unchanged")
	}
}
