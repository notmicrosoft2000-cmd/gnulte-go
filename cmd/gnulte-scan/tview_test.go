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
	"fmt"
	"strings"
	"testing"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/scanner"
)

func sampleRows() []discover.Row {
	return []discover.Row{
		{IP: "192.168.1.10", MAC: "AA:AA:AA:AA:AA:01", Vendor: "Apple", Hostname: "mbp", Type: "Computer", OS: "macOS 15"},
		{IP: "192.168.1.2", MAC: "BB:BB:BB:BB:BB:02", Vendor: "Xiaomi", Hostname: "", Type: "Mobile", OS: "Android 13"},
		{IP: "192.168.1.99", MAC: "CC:CC:CC:CC:CC:03", Vendor: "Frontiir", Hostname: "gw", Type: "Router/Gateway", OS: "OpenWrt"},
		{IP: "192.168.1.50", MAC: "DD:DD:DD:DD:DD:04", Vendor: "Synology", Hostname: "nas", Type: "NAS", OS: "DSM 7"},
	}
}

func newTable() *tvTable {
	t := &tvTable{rows: sampleRows(), sortBy: sortIP, detail: -1}
	t.build()
	return t
}

func TestTVFilter(t *testing.T) {
	tab := newTable()
	if len(tab.view) != 4 {
		t.Fatalf("unfiltered view has %d rows, want 4", len(tab.view))
	}
	tab.filter = []rune("xiaomi")
	tab.build()
	if len(tab.view) != 1 {
		t.Fatalf("filter xiaomi kept %d rows, want 1", len(tab.view))
	}
	if tab.view[0].r.IP != "192.168.1.2" {
		t.Errorf("filter matched %s, want the Xiaomi", tab.view[0].r.IP)
	}
	// Case-insensitive match on hostname + os.
	tab.filter = []rune("NAS")
	tab.build()
	if len(tab.view) != 1 || tab.view[0].r.IP != "192.168.1.50" {
		t.Errorf("hostname/os filter wrong: %+v", tab.view)
	}
}

func TestTVSort(t *testing.T) {
	tab := newTable()
	if tab.view[0].r.IP != "192.168.1.2" {
		t.Fatalf("default IP sort first row %s, want 192.168.1.2", tab.view[0].r.IP)
	}
	tab.sortBy = sortVendor
	tab.desc = true
	tab.build()
	if tab.view[0].r.Vendor != "Xiaomi" {
		t.Errorf("descending vendor sort first is %s, want Xiaomi", tab.view[0].r.Vendor)
	}
	tab.sortBy = sortType
	tab.desc = false
	tab.build()
	if tab.view[0].r.Type != "Computer" {
		t.Errorf("type sort first is %s, want Computer", tab.view[0].r.Type)
	}
	tab.sortBy = sortHostname
	tab.desc = false
	tab.build()
	if tab.view[0].r.Hostname != "" {
		t.Errorf("hostname sort first is %q, want empty (sorts first)", tab.view[0].r.Hostname)
	}
	tab.desc = true
	tab.build()
	if tab.view[0].r.Hostname != "nas" {
		t.Errorf("descending hostname sort first is %q, want nas", tab.view[0].r.Hostname)
	}
}

func TestTVCursorClamps(t *testing.T) {
	tab := newTable()
	tab.cursor = 9
	tab.build()
	if tab.cursor != 0 {
		t.Errorf("cursor clamped to %d, want 0", tab.cursor)
	}
	tab.detail = 7
	tab.build()
	if tab.detail != -1 {
		t.Errorf("detail out-of-range should clear, got %d", tab.detail)
	}
}

// TestTVApplyDeltaFold live re-scans into the table: hosts that vanish stay
// visible with the ▼ GONE mark, brand-new hosts appear with ▲ NEW, and the
// movement counts feed the summary.
func TestTVApplyDeltaFold(t *testing.T) {
	tab := newTable()
	next := []discover.Row{
		{IP: "192.168.1.2", MAC: "BB:BB:BB:BB:BB:02", Vendor: "Xiaomi", Hostname: "", Type: "Mobile"},              // unchanged
		{IP: "192.168.1.99", MAC: "CC:CC:CC:CC:CC:03", Vendor: "Frontiir", Hostname: "gw", Type: "Router/Gateway"}, // unchanged
		{IP: "192.168.1.200", MAC: "EE:EE:EE:EE:EE:0E", Vendor: "Tesla", Hostname: "car", Type: "Car"},             // brand new
		// 192.168.1.10 and .50 dropped off the network.
	}
	tab.applyDelta(next)
	if tab.delta["192.168.1.10"] != scanner.DeltaGone {
		t.Errorf(".10 = %v, want GONE", tab.delta["192.168.1.10"])
	}
	if tab.delta["192.168.1.50"] != scanner.DeltaGone {
		t.Errorf(".50 = %v, want GONE", tab.delta["192.168.1.50"])
	}
	if tab.delta["192.168.1.200"] != scanner.DeltaNew {
		t.Errorf(".200 = %v, want NEW", tab.delta["192.168.1.200"])
	}
	if tab.delta["192.168.1.2"] != scanner.DeltaAlive {
		t.Errorf(".2 = %v, want ALIVE", tab.delta["192.168.1.2"])
	}
	// GONE hosts must still appear in the visible rows (dimmed, marked).
	ips := map[string]bool{}
	for _, v := range tab.view {
		ips[v.r.IP] = true
	}
	for _, want := range []string{"192.168.1.10", "192.168.1.50", "192.168.1.2", "192.168.1.99", "192.168.1.200"} {
		if !ips[want] {
			t.Errorf("row %s missing after delta fold (visible %v)", want, ips)
		}
	}
	newN, goneN, changedN, _ := tab.delta.Counts()
	if newN != 1 || goneN != 2 || changedN != 0 {
		t.Errorf("counts = new %d gone %d changed %d, want 1/2/0", newN, goneN, changedN)
	}
}

// TestTVDeltaMark: the table stays quiet for hosts that simply stayed alive.
func TestTVDeltaMark(t *testing.T) {
	tab := newTable()
	if tab.deltaMark("192.168.1.2") != " " {
		t.Fatal("deltaMark without a delta must be blank")
	}
	tab.applyDelta(sampleRows())
	if got := tab.deltaMark("192.168.1.10"); got != "·" {
		t.Errorf("alive mark = %q, want ·", got)
	}
}

func TestTVMatchesSpansManyFields(t *testing.T) {
	row := tvRow{r: discover.Row{IP: "10.0.0.5", MAC: "EE:EE:EE:EE:EE:05", Vendor: "Canon", Hostname: "printer", Type: "Printer", OS: "Canon firmware"}}
	for _, q := range []string{"10.0.0", "EE:EE", "canon", "printer", "firmware"} {
		if !row.matches(q) {
			t.Errorf("row should match %q", q)
		}
	}
	if row.matches("raspberry") {
		t.Error("row must not match a random term")
	}
}

func TestRawTableLinesHasGutters(t *testing.T) {
	rows := sampleRows()
	for _, ln := range rawTableLines(rows) {
		if len(ln) != 0 && strings.Contains(ln, "CBFrontiir") {
			t.Errorf("mac and vendor cells collided: %q", ln)
		}
	}
	has := false
	for _, ln := range rawTableLines(rows) {
		if strings.Contains(ln, "OS") {
			has = true
		}
	}
	if !has {
		t.Error("snapshot should include an OS column")
	}
}

func TestTabBarShowsAllWindows(t *testing.T) {
	tab := newTable()
	bar := tab.tabBar()
	for _, want := range []string{"[1] Devices", "[2] Log", "[3] Summary"} {
		if !strings.Contains(bar, want) {
			t.Errorf("tab bar missing %q: %q", want, bar)
		}
	}
}

func TestLogLinesTailShowsNewest(t *testing.T) {
	tab := newTable()
	log := make([]string, 40)
	for i := range log {
		log[i] = fmt.Sprintf("line-%02d", i)
	}
	tab.log = log
	tab.logOff = 0 // tail
	lines := tab.logLines()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "line-39") {
		t.Errorf("tail window missing newest line:\n%s", joined)
	}
	// Scrolling far up reveals line-00 and hides the newest.
	tab.logOff = 100 // clamped to the top of the log
	lines = tab.logLines()
	joined = strings.Join(lines, "\n")
	if !strings.Contains(joined, "line-00") {
		t.Errorf("scrolled window missing oldest line:\n%s", joined)
	}
	if strings.Contains(joined, "line-39") {
		t.Errorf("scrolled window still showing newest line:\n%s", joined)
	}
}

func TestSummaryLinesCountsByTypeAndPorts(t *testing.T) {
	tab := newTable()
	tab.rows = sampleRows()
	tab.rows[1].Ports = "443,22"
	tab.rows[3].Ports = "5000"
	lines := tab.summaryLines()
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"Scan summary — 4 host(s)", "Router/Gateway", "Computer", "NAS", "open ports total   3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary missing %q:\n%s", want, joined)
		}
	}
}
