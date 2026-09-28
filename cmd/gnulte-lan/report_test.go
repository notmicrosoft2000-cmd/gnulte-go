package main

import (
	"os"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
)

// TestWriteSampleReport renders a realistic watch report to
// GNULTE_SAMPLE_REPORT (or /tmp/gnulte-lan-sample.html) so the layout can be
// reviewed in a browser without a live session. Skipped unless the env var is
// set.
func TestWriteSampleReport(t *testing.T) {
	path := os.Getenv("GNULTE_SAMPLE_REPORT")
	if path == "" {
		t.Skip("set GNULTE_SAMPLE_REPORT to generate a sample report")
	}
	start := time.Now().Add(-3 * time.Minute)
	end := time.Now()

	hosts := []string{"192.168.100.13", "192.168.100.40", "192.168.100.207"}
	info := map[string]hostInfo{
		"192.168.100.13":  {IP: "192.168.100.13", MAC: "A4:83:E7:12:34:56", Vendor: "Apple, Inc.", Type: "phone", Host: "cassie-phone"},
		"192.168.100.40":  {IP: "192.168.100.40", MAC: "00:1A:2B:3C:4D:5E", Vendor: "Raspberry Pi Foundation", Type: "linux", Host: "nest-cam-2"},
		"192.168.100.207": {IP: "192.168.100.207", MAC: "3C:22:FB:AA:BB:CC", Vendor: "Intel Corporate", Type: "laptop", Host: "neptune-t430"},
	}
	stats := map[string]*hostStat{}
	for i, ip := range hosts {
		st := &hostStat{}
		// Realistic ping traces: a phone at ~130ms, a flaky camera, a laptop.
		var bases []int
		switch i {
		case 0:
			bases = []int{129, 131, 128, 136, 140, 133, 129, 127, 146, 138, 131, 129, 135, 141, 128, 132, 137, 143, 130, 126, 134, 139, 144, 129, 131, 136, 142, 127, 133, 138, 130, 135, 140, 128, 132, 137, 131, 129, 134, 139, 128, 133, 138, 130}
		case 1:
			bases = []int{255, 262, 271, 268, 289, 314, 260, 275, -1, 296, 271, 258, 312, 277, 263, 348, 285, 269, 302, 258, -1, 281, 266, 387, 274, 259, 296, 318, 270, 284, 293, 273, 352, 385, -1, 270}
		default:
			bases = []int{55, 61, 58, 63, 60, 57, 64, 59, 62, 56, 65, 60, 58, 61, 57, 63, 60, 56, 59, 64, 58, 62, 61, 57, 63, 60, 58, 62, 59}
		}
		for _, v := range bases {
			st.ping.add(v, 60)
		}
		// Rate history to feed the sparklines and totals.
		for t := 0; t < len(bases); t++ {
			switch i {
			case 0:
				st.addRate(120000+int64(t)*7000, 40000+int64(t)*2000, 60) // streaming-ish phone
			case 1:
				st.addRate(8000+int64(t)*400, 30000+int64(t)*1500, 60) // uploady camera
			default:
				st.addRate(90000+int64(t)*3000, 25000+int64(t)*800, 60) // browsing laptop
			}
		}
		stats[ip] = st
	}

	flows := []traffic.Flow{
		{A: "192.168.100.13:443", B: "151.101.1.69:443", AB: 23_400_000, BA: 1_200_000, ABp: 18_400, BAp: 2_210},
		{A: "192.168.100.40:554", B: "192.168.100.207:49321", AB: 1_900_000, BA: 12_400_000, ABp: 8_410, BAp: 22_010},
		{A: "192.168.100.207:443", B: "142.250.72.14:443", AB: 14_700_000, BA: 900_000, ABp: 12_300, BAp: 1_280},
		{A: "8.8.8.8:53", B: "192.168.100.207:59217", AB: 22_000, BA: 96_000, ABp: 310, BAp: 180},
		{A: "192.168.100.13:62078", B: "17.248.140.6:5228", AB: 4_100_000, BA: 220_000, ABp: 2_900, BAp: 600},
	}
	log := []string{
		"  ── wlan0 ───────────────────────────────────────────",
		"  LIVE LAN WATCH  every 1s · Ctrl+C to stop",
		"",
		"▸ 192.168.100.13   ↓ 1.2MB/s (400 pkt/s)   ↑ 40KB/s (12 pkt/s)",
		"   A4:83:E7:12:34:56 · Apple, Inc. · phone · cassie-phone",
		"   ping 129ms · avg 130ms · loss 0%  ▂▃▅▂▃▅",
		"  TOP TALKERS  this interval · bold = watched host",
		"   192.168.100.13:443  ⇄  151.101.1.69:443   ↓ 23MB/s  ↑ 1.2MB/s",
		"  TOTAL              ↓ 25MB/s (480 pkt/s)    ↑ 13MB/s (90 pkt/s)",
		"  [15:12:04]",
	}
	sess := &lanSession{
		iface:  "wlan0",
		subnet: "192.168.100.0/24",
		start:  start,
		end:    end,
		ticks:  180,
		iv:     1,
		hosts:  hosts,
		info:   info,
		stats:  stats,
		flows:  flows,
		log:    log,
	}
	if err := writeReport(path, sess); err != nil {
		t.Fatal(err)
	}
}
