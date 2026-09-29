package engine

import "testing"

const sampleQdisc = `qdisc htb 1: root refcnt 2 r2q 10 default 999 direct_packets_stat 0
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
qdisc netem 10: parent 1:10 limit 1000 delay 1500.0ms  300.0ms
 Sent 123456 bytes 789 pkt (dropped 34, overlimits 0 requeues 0)
 backlog 4321b 90p requeues 0
 rate 51200bit 8pps backlog 4321b 90p requeues 0
  delayed 456 packets
  reordered 12 packets
  fast 0 packets
  maybe_dropped 0 packets
  dropped 0 packets
`

func TestParseQdiscStatsNetem(t *testing.T) {
	q := parseQdiscStats(sampleQdisc, "wlan0")
	if !q.Found {
		t.Fatal("netem leaf not found")
	}
	if q.Limit != 1000 {
		t.Errorf("limit = %d, want 1000", q.Limit)
	}
	if q.DelayMs != 1500 {
		t.Errorf("delay = %dms, want 1500", q.DelayMs)
	}
	if q.Delayed != 456 {
		t.Errorf("delayed = %d, want 456", q.Delayed)
	}
	if q.Reordered != 12 {
		t.Errorf("reordered = %d, want 12", q.Reordered)
	}
	if q.Dropped != 34 {
		t.Errorf("dropped = %d, want 34", q.Dropped)
	}
	if q.Backlog != 90 {
		t.Errorf("backlog = %d, want 90 pkt", q.Backlog)
	}
}

func TestParseQdiscStatsNoNetem(t *testing.T) {
	q := parseQdiscStats("qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1\n", "eth0")
	if q.Found {
		t.Fatal("a non-netem tree must not report telemetry")
	}
}

func TestParseQdiscStatsEmpty(t *testing.T) {
	if q := parseQdiscStats("", "eth0"); q.Found || q.Delayed != 0 || q.Backlog != 0 {
		t.Fatalf("empty dump should be a clean miss: %#v", q)
	}
}

func TestParseQdiscStatsBlockDelimiter(t *testing.T) {
	// A second qdisc after the netem leaf must not bleed into the netem block.
	two := sampleQdisc + "qdisc fq_codel 20: parent 1:20 limit 10240p flows 1024 quantum 1514\n Sent 1 bytes 1 pkt (dropped 999, overlimits 0 requeues 0)\n"
	q := parseQdiscStats(two, "wlan0")
	if q.Dropped != 34 {
		t.Errorf("dropped = %d, want 34 (later qdisc leaks)", q.Dropped)
	}
}

func TestParseQdiscDroppedOnOwnLine(t *testing.T) {
	// Kernels that keep the parenthetical drop at zero and list drops on a
	// dedicated line must still report them.
	dump := `qdisc netem 10: parent 1:10 limit 1000 delay 500.0ms  100.0ms
 Sent 100 bytes 10 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
  delayed 20 packets
  reordered 3 packets
  fast 0 packets
  maybe_dropped 0 packets
  dropped 7 packets
`
	q := parseQdiscStats(dump, "eth0")
	if q.Dropped != 7 {
		t.Errorf("dropped = %d, want 7 from the dedicated line", q.Dropped)
	}
}