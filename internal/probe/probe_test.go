package probe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// swapRawPing replaces the in-Go probe for one test and restores it after.
func swapRawPing(t *testing.T, fn func(context.Context, string, time.Duration) (int, int, bool, error)) {
	t.Helper()
	old := rawPing
	rawPing = fn
	t.Cleanup(func() { rawPing = old })
}

// TestPingPrefersTheInGoProbe is the whole point of 16.7: when the raw-ICMP
// core can run, Ping must return its numbers and never touch the ping binary.
// PATH is emptied so a fallback would fail and return -1, which makes the
// assertion discriminating rather than merely true.
func TestPingPrefersTheInGoProbe(t *testing.T) {
	t.Setenv("PATH", "")
	swapRawPing(t, func(context.Context, string, time.Duration) (int, int, bool, error) {
		return 7, 63, true, nil
	})
	rtt, ttl := Ping(context.Background(), "10.0.0.1", time.Second)
	if rtt != 7 || ttl != 63 {
		t.Fatalf("Ping = rtt %d ttl %d, want the in-Go 7/63 (did it shell out to ping?)", rtt, ttl)
	}
}

// TestPingDoesNotShellOutOnSilence: a raw probe that ran fine but got no reply
// is silence, and silence must be reported as -1 instead of being retried with
// a subprocess. A stand-in ping that *would* answer sits on PATH, so if the code
// wrongly fell back on silence this test would read 4/42 instead of -1.
func TestPingDoesNotShellOutOnSilence(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "ping")
	body := "#!/bin/sh\necho \"64 bytes from 127.0.0.1: icmp_seq=1 ttl=42 time=4.2 ms\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("writing fake ping: %v", err)
	}
	t.Setenv("PATH", dir)
	calls := 0
	swapRawPing(t, func(context.Context, string, time.Duration) (int, int, bool, error) {
		calls++
		return -1, 0, false, nil
	})
	if rtt, _ := Ping(context.Background(), "10.0.0.2", time.Second); rtt != -1 {
		t.Fatalf("Ping = %d, want -1 for a silent target (fell back to ping?)", rtt)
	}
	if calls != 1 {
		t.Fatalf("raw probe ran %d times, want exactly 1", calls)
	}
}

// TestPingFallsBackToSystemPing covers the non-root path: when no raw socket is
// available the in-Go probe reports an error and Ping must run the system ping
// and parse its output, exactly as the non-root tools always have. A stand-in
// script on PATH produces a fixed reply, so the parsed RTT and TTL prove the
// subprocess path is intact.
func TestPingFallsBackToSystemPing(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "ping")
	body := "#!/bin/sh\necho \"64 bytes from 127.0.0.1: icmp_seq=1 ttl=42 time=4.2 ms\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("writing fake ping: %v", err)
	}
	t.Setenv("PATH", dir)
	swapRawPing(t, func(context.Context, string, time.Duration) (int, int, bool, error) {
		return -1, 0, false, fmt.Errorf("no raw socket")
	})
	rtt, ttl := Ping(context.Background(), "127.0.0.1", time.Second)
	if rtt != 4 || ttl != 42 {
		t.Fatalf("Ping = rtt %d ttl %d, want the subprocess parse 4/42", rtt, ttl)
	}
}

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
