package probe

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestPingLocalhost(t *testing.T) {
	rtt, ttl := Ping(context.Background(), "127.0.0.1", time.Second)
	if rtt < 0 {
		t.Fatalf("localhost should answer echo, got rtt=%d", rtt)
	}
	if ttl == 0 {
		t.Error("localhost reply should carry a TTL")
	}
}

func TestParseMillis(t *testing.T) {
	ttl := 64
	for _, tc := range []struct{ in, want string }{
		{"0.042", "0"},
		{"11.0", "11"},
		{"3", "3"},
		{"<1", "1"},
		{"garbage", "-1"},
	} {
		rtt := parseMillis(tc.in, ttl)
		if got := strconv.Itoa(rtt); got != tc.want {
			t.Errorf("parseMillis(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestClosedPortRefused(t *testing.T) {
	// Port 1 has no listener on loopback: Linux answers with RST, which is a
	// deterministic "host alive" signal without touching the network.
	res := ProbeTCP(context.Background(), "127.0.0.1", []int{1})
	if len(res.TCP) == 0 {
		t.Fatal("expected a TCP verdict")
	}
	if !res.Alive() {
		t.Errorf("RST-answering host should report alive, got %+v", res.TCP[0])
	}
	if res.TCP[0].State != Refused {
		t.Errorf("closed loopback port should refuse, got %s", res.TCP[0].State)
	}
}

func TestResultLatencyUsesICMPFirst(t *testing.T) {
	res := Result{ICMP: true, ICMPMs: 42}
	if res.Latency() != 42 {
		t.Errorf("icmp latency should be preferred, got %d", res.Latency())
	}
	res = Result{TCP: []PortResult{{Port: 53, State: Open, RTTMs: 9}, {Port: 80, State: Open, RTTMs: 4}}}
	if res.Latency() != 4 {
		t.Errorf("fastest tcp reply should win, got %d", res.Latency())
	}
	res = Result{TCP: []PortResult{{Port: 80, State: Timeout, RTTMs: 1200}}}
	if res.Alive() || res.Latency() != -1 {
		t.Error("a silent TCP probe must not be alive")
	}
}

func TestNoteKinds(t *testing.T) {
	if n := (Result{ICMP: true, ICMPMs: 12}).Note(); n != "icmp 12ms" {
		t.Errorf("icmp note wrong: %q", n)
	}
	if n := (Result{TCP: []PortResult{{Port: 443, State: Open, RTTMs: 5}}}).Note(); n != "tcp:443 5ms" {
		t.Errorf("open note wrong: %q", n)
	}
	if n := (Result{TCP: []PortResult{{Port: 80, State: Refused, RTTMs: 2}}}).Note(); n != "tcp:80/refused 2ms" {
		t.Errorf("refused note wrong: %q", n)
	}
}
