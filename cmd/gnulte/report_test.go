package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/monitor"
)

// TestSessionHTMLStructure pins the polished report layout: a summary table
// with per-target rows, status pills, per-target cards with an SVG timeline,
// and the full log history — all escaped for hostile log content.
func TestSessionHTMLStructure(t *testing.T) {
	start := time.Date(2026, 9, 28, 15, 12, 4, 0, time.UTC)
	end := start.Add(1*time.Minute + 3*time.Second)
	res := []monitor.Result{
		{
			IP: "192.168.1.2",
			Stats: monitor.Stats{Count: 10, Drops: 0, Total: 1200,
				Min: 100, Max: 150, Samples: []int{100, 110, 120, 130, 145, 110, 100, 125, 135, 125}},
		},
		{
			IP: "192.168.1.10",
			Stats: monitor.Stats{Count: 8, Drops: 6, Total: 2400,
				Min: 250, Max: 400, Samples: []int{250, 300, 350, 400, 300, 275, 290, 310}},
		},
	}
	log := []string{
		"  [✓] Elevate done.",
		`  $ tc qdisc add dev eth0 root netem delay 150ms  <-- unwise " & tags`,
	}

	html := sessionHTML(log, res, start, end)
	for _, want := range []string{
		"<section><h2>Target summary</h2>",
		"<h2>Session summary</h2>",
		"<th>P95</th>",
		"MOS",
		"p95",
		"Full log history",
		"192.168.1.2", "192.168.1.10",
		`class="mono">192.168.1.2</td>`,
		`class="pill up"`,  // 0% loss -> UP
		`class="pill bad"`, // 42.9% loss -> UNSTABLE
		"latency timeline",
		"10 sample(s)",            // card counts attempts, not only successes
		"43%",                     // 6 drops / (8+6) attempts
		"&lt;", "&quot;", "&amp;", // hostile log is escaped
		"63 s", // duration chip
	} {
		if !strings.Contains(html, want) {
			t.Errorf("sessionHTML missing %q", want)
		}
	}
	if strings.Contains(html, "unwise\" & tags") {
		t.Error("log content was not HTML-escaped")
	}
	if strings.Count(html, "<svg") < 2 {
		t.Error("expected one SVG timeline per target card")
	}
}

// TestSVGChartEmpty guards against a crash on zero samples (short sessions).
func TestSVGChartEmpty(t *testing.T) {
	out := svgChart(nil)
	if !strings.Contains(out, "no latency samples") {
		t.Errorf("empty chart should say so: %s", out)
	}
	if out := svgChart([]int{42}); !strings.Contains(out, "polyline") {
		t.Errorf("single-sample chart missing polyline: %s", out)
	}
}

// TestIPLess verifies numeric ordering beats byte-wise string order.
func TestIPLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"192.168.1.2", "192.168.1.10", true},
		{"10.0.0.1", "192.168.1.1", true},
		{"192.168.1.10", "192.168.1.2", false},
		{"192.168.1.2", "192.168.1.2", false},
	}
	for _, tc := range cases {
		if got := ipLess(tc.a, tc.b); got != tc.want {
			t.Errorf("ipLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestWriteSampleReport renders a realistic report to GNULTE_SAMPLE_REPORT (or
// /tmp/gnulte-sample-report.html) so the polished layout can be reviewed in a
// browser without a live session. Skipped unless the env var is set.
func TestWriteSampleReport(t *testing.T) {
	path := os.Getenv("GNULTE_SAMPLE_REPORT")
	if path == "" {
		t.Skip("set GNULTE_SAMPLE_REPORT to generate a sample report")
	}
	start := time.Date(2026, 9, 28, 15, 12, 4, 0, time.UTC)
	end := start.Add(95 * time.Second)
	res := []monitor.Result{
		{
			IP: "192.168.100.13",
			Stats: monitor.Stats{Count: 45, Drops: 0, Total: 6240,
				Min: 118, Max: 183,
				Samples: []int{129, 131, 128, 136, 140, 133, 129, 127, 146, 138, 131, 129, 135, 141, 128, 132, 137, 143, 130, 126, 134, 139, 144, 129, 131, 136, 142, 127, 133, 138, 130, 135, 140, 128, 132, 137, 131, 129, 134, 139, 128, 133, 138, 130, 183}},
		},
		{
			IP: "192.168.100.40",
			Stats: monitor.Stats{Count: 34, Drops: 5, Total: 9750,
				Min: 241, Max: 398,
				Samples: []int{255, 262, 271, 268, 289, 314, 260, 275, 398, 296, 271, 258, 312, 277, 263, 348, 285, 269, 302, 258, 330, 281, 266, 387, 274, 259, 296, 318, 270, 284, 293, 273, 352, 385}},
		},
		{
			IP: "192.168.100.207",
			Stats: monitor.Stats{Count: 30, Drops: 18, Total: 1980,
				Min: 51, Max: 96,
				Samples: []int{55, 61, 58, 63, 60, 57, 64, 59, 62, 56, 65, 60, 58, 96, 61, 57, 63, 60, 56, 59, 64, 58, 62, 61, 57, 63, 60, 58, 62, 59}},
		},
	}
	log := []string{
		"  GNULTE v13.1 (Go) — interactive network testing toolkit",
		"  $ sudo -E /usr/local/bin/gnulte",
		"  [✓] Sudo access granted — running with administrator privileges.",
		"  [✓] Session armed — pinging 192.168.100.13, 192.168.100.40, 192.168.100.207",
		"  $ tc qdisc add dev wlan0 root netem delay 150ms 300ms distribution normal",
		"  #001 [15:12:05] ✓ 192.168.100.13        129ms",
		"  #002 [15:12:05] ✓ 192.168.100.13        131ms",
		"  #021 [15:13:02] ✗ 192.168.100.207      unreachable  timeout",
		"  [✓] tc qdisc del dev wlan0 root netem",
		"  Test finished — normal connectivity restored.",
	}
	if err := os.WriteFile(path, []byte(sessionHTML(log, res, start, end)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("sample report written to %s", path)
}
