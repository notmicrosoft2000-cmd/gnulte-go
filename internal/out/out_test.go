package out

import (
	"bytes"
	"strings"
	"testing"

	"gnulte-go/internal/discover"
)

func TestIPLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"192.168.1.2", "192.168.1.10", true},
		{"10.0.0.200", "10.0.1.1", true},
		{"192.168.1.10", "192.168.1.2", false},
		{"1.2.3.4", "1.2.3.4", false},
	}
	for _, c := range cases {
		if got := ipLess(c.a, c.b); got != c.want {
			t.Errorf("ipLess(%s,%s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestAtoi(t *testing.T) {
	if atoi("42") != 42 {
		t.Error("atoi(42) failed")
	}
	if atoi("12x") != 0 {
		t.Error("atoi should reject non-numeric")
	}
}

func TestSortByIP(t *testing.T) {
	rows := []discover.Row{{IP: "192.168.1.10"}, {IP: "192.168.1.2"}, {IP: "10.1.1.1"}}
	SortByIP(rows)
	want := []string{"10.1.1.1", "192.168.1.2", "192.168.1.10"}
	for i, w := range want {
		if rows[i].IP != w {
			t.Errorf("row[%d] = %s, want %s", i, rows[i].IP, w)
		}
	}
}

// TestTableShowsPortsAndOSFromLaterRow: the column set must be derived from
// every row. With IP-sorted rows the first host can be a bare ARP neighbour
// while a later one carries ports or an OS guess.
func TestTableShowsPortsAndOSFromLaterRow(t *testing.T) {
	var b bytes.Buffer
	rows := []discover.Row{
		{IP: "10.0.0.1"},
		{IP: "10.0.0.2", Ports: "22,80", OS: "Linux"},
	}
	Table(&b, rows)
	got := b.String()
	if !strings.Contains(got, "PORTS") || !strings.Contains(got, "OS") {
		t.Errorf("PORTS/OS headers missing when only a later row has them:\n%s", got)
	}
	if !strings.Contains(got, "22,80") || !strings.Contains(got, "Linux") {
		t.Errorf("later row values missing:\n%s", got)
	}
}

// TestTableOSColumnWithoutPorts: headers and cells must stay aligned when OS is
// present but no row has ports. The old code counted only the header length, so
// it filled the OS column with the ports placeholder ("-") and dropped the OS.
func TestTableOSColumnWithoutPorts(t *testing.T) {
	var b bytes.Buffer
	Table(&b, []discover.Row{{IP: "10.0.0.1", OS: "Linux"}})
	got := b.String()
	if strings.Contains(got, "PORTS") {
		t.Fatalf("PORTS header shown with no ports:\n%s", got)
	}
	if !strings.Contains(got, "Linux") {
		t.Fatalf("OS value dropped / misaligned:\n%s", got)
	}
}

// TestTableLinesShareOneWidth: the rule lines, the header, and every row must
// line up — the separator is built from the same per-column widths.
func TestTableLinesShareOneWidth(t *testing.T) {
	var b bytes.Buffer
	rows := []discover.Row{
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Acme", Hostname: "host", Type: "pc", Ports: "22,80", OS: "Linux"},
		{IP: "10.0.0.2"},
	}
	Table(&b, rows)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected rule/header/rows, got %d lines", len(lines))
	}
	w := len([]rune(lines[0]))
	for i, ln := range lines {
		if got := len([]rune(ln)); got != w {
			t.Errorf("line %d width = %d, want %d (rules must match the header)\n%s", i, got, w, b.String())
		}
	}
}

// TestYAMLBannersAreKeyedSequence: banners must nest under a `banners:` key
// like services do, not appear as stray `- banner:` items that break the host
// mapping.
func TestYAMLBannersAreKeyedSequence(t *testing.T) {
	var b bytes.Buffer
	rows := []discover.Row{{IP: "10.0.0.1", Banners: []string{"22 (ssh): SSH-2.0", "80 (http): nginx"}}}
	if err := YAML(&b, rows); err != nil {
		t.Fatalf("YAML: %v", err)
	}
	got := b.String()
	if !strings.Contains(got, "    banners:\n") {
		t.Errorf("banners key missing:\n%s", got)
	}
	if strings.Contains(got, "- banner:") {
		t.Errorf("banners emitted as stray list items:\n%s", got)
	}
	if n := strings.Count(got, "      - \""); n != 2 {
		t.Errorf("want two nested banner entries, got %d:\n%s", n, got)
	}
}
