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

package toptalk

import (
	"strings"
	"testing"

	"gnulte-go/internal/traffic"
)

func TestRowsConvertAndSortByCombinedRate(t *testing.T) {
	rates := map[string]traffic.Rate{
		"10.0.0.1": {RXBytes: 2048, TXBytes: 1024, RXPkts: 20, TXPkts: 10},
		"10.0.0.2": {RXBytes: 4096},
		"10.0.0.3": {RXBytes: 100, TXBytes: 100},
	}
	rows := Rows(rates, 2, nil)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	wantOrder := []string{"10.0.0.2", "10.0.0.1", "10.0.0.3"}
	for i, want := range wantOrder {
		if rows[i].Host != want {
			t.Fatalf("row %d host = %s, want %s (order %+v)", i, rows[i].Host, want, rows)
		}
	}
	if rows[1].Down != 1024 || rows[1].Up != 512 || rows[1].Total() != 1536 {
		t.Fatalf("10.0.0.1 rates = %+v, want down 1024 up 512 total 1536", rows[1])
	}
	if rows[1].DownPkts != 10 || rows[1].UpPkts != 5 {
		t.Fatalf("10.0.0.1 packet rates = %+v", rows[1])
	}
}

func TestRowsTieBreakByHost(t *testing.T) {
	// Equal combined rates must order by host so the output is deterministic.
	rates := map[string]traffic.Rate{
		"10.0.0.9": {RXBytes: 100},
		"10.0.0.7": {RXBytes: 100},
		"10.0.0.8": {RXBytes: 100},
	}
	rows := Rows(rates, 1, nil)
	want := []string{"10.0.0.7", "10.0.0.8", "10.0.0.9"}
	for i, w := range want {
		if rows[i].Host != w {
			t.Fatalf("tie row %d = %s, want %s (order %+v)", i, rows[i].Host, w, rows)
		}
	}
}

func TestRowsFilterAndZeroSeconds(t *testing.T) {
	rates := map[string]traffic.Rate{
		"192.168.1.10": {RXBytes: 500},
		"192.168.1.20": {RXBytes: 900},
	}
	only := Rows(rates, 1, func(h string) bool { return strings.HasSuffix(h, ".10") })
	if len(only) != 1 || only[0].Host != "192.168.1.10" {
		t.Fatalf("filtered rows = %+v, want only .10", only)
	}
	// A zero interval must not divide by zero; the raw count is the rate.
	raw := Rows(map[string]traffic.Rate{"h": {RXBytes: 7}}, 0, nil)
	if len(raw) != 1 || raw[0].Down != 7 {
		t.Fatalf("zero-second rows = %+v, want the raw count", raw)
	}
}

func TestFlowRowsSortAndFilter(t *testing.T) {
	flows := []traffic.Flow{
		{A: "a:1", B: "b:2", AB: 100, BA: 50},
		{A: "c:3", B: "d:4", AB: 10, BA: 5},
	}
	rows := FlowRows(flows, 1, nil)
	if len(rows) != 2 || rows[0].A != "a:1" || rows[0].Total() != 150 {
		t.Fatalf("flow rows = %+v, want a-b first with total 150", rows)
	}
	// Either endpoint passing the filter keeps the conversation.
	kept := FlowRows(flows, 1, func(ep string) bool { return strings.HasPrefix(ep, "c:") })
	if len(kept) != 1 || kept[0].A != "c:3" {
		t.Fatalf("filtered flow rows = %+v, want only c-d", kept)
	}
}

func TestFlowRowsTieBreakByEndpoints(t *testing.T) {
	// Equal totals order by A then B, so the ranking is deterministic.
	flows := []traffic.Flow{
		{A: "b:1", B: "z:1", AB: 100},
		{A: "a:1", B: "z:1", AB: 100},
		{A: "a:1", B: "a:2", AB: 100},
	}
	rows := FlowRows(flows, 1, nil)
	want := [][2]string{{"a:1", "a:2"}, {"a:1", "z:1"}, {"b:1", "z:1"}}
	for i, w := range want {
		if rows[i].A != w[0] || rows[i].B != w[1] {
			t.Fatalf("tie flow %d = %s->%s, want %s->%s (order %+v)", i, rows[i].A, rows[i].B, w[0], w[1], rows)
		}
	}
}

func TestPeersCountsDistinctPartners(t *testing.T) {
	flows := []traffic.Flow{
		{A: "10.0.0.1:80", B: "10.0.0.2:5000"},
		{A: "10.0.0.2:5001", B: "10.0.0.3:443"},
		{A: "10.0.0.2:5002", B: "10.0.0.1:80"}, // repeat partner, still one peer
	}
	got := Peers(flows)
	want := map[string]int{"10.0.0.1": 1, "10.0.0.2": 2, "10.0.0.3": 1}
	for host, n := range want {
		if got[host] != n {
			t.Errorf("peers[%s] = %d, want %d (%+v)", host, got[host], n, got)
		}
	}
}

func TestHostOf(t *testing.T) {
	if got := HostOf("10.0.0.1:443"); got != "10.0.0.1" {
		t.Errorf("HostOf(ip:port) = %q", got)
	}
	if got := HostOf("10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("HostOf(ip) = %q", got)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:          "0 B",
		1023:       "1023 B",
		1024:       "1.0 KiB",
		1536:       "1.5 KiB",
		1048576:    "1.0 MiB",
		1073741824: "1.0 GiB",
		-1024:      "-1.0 KiB",
	}
	for in, want := range cases {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := HumanRate(1536); got != "1.5 KiB/s" {
		t.Errorf("HumanRate(1536) = %q, want 1.5 KiB/s", got)
	}
}

func TestBar(t *testing.T) {
	cases := []struct {
		v, max int64
		width  int
		want   string
	}{
		{100, 100, 4, "████"},
		{50, 100, 4, "██··"},
		{0, 100, 4, "····"},
		{10, 0, 4, "····"},
		{10, 100, 0, ""},
	}
	for _, tc := range cases {
		if got := Bar(tc.v, tc.max, tc.width); got != tc.want {
			t.Errorf("Bar(%d,%d,%d) = %q, want %q", tc.v, tc.max, tc.width, got, tc.want)
		}
	}
	// A rate above the max must not overflow the width.
	if got := Bar(200, 100, 4); got != "████" {
		t.Errorf("Bar over max = %q, want a full four cells", got)
	}
}
