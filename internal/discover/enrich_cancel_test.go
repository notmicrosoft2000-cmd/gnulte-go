package discover

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// A cancelled context must end the identification pass at once. This is the
// difference between a Ctrl+C that stops a live watch and one that leaves the
// operator watching a frozen screen for the length of every remaining timeout:
// the mDNS listen and each serial NetBIOS query both used to run out their full
// fallback window because a cancelled context carries no deadline.
func TestEnrichHostnamesHonoursCancel(t *testing.T) {
	rows := []Row{{IP: "192.0.2.1"}, {IP: "192.0.2.2"}, {IP: "192.0.2.3"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	EnrichHostnames(ctx, rows)
	elapsed := time.Since(start)

	// The unroutable 192.0.2.0/24 answers nothing, so every query would have
	// burnt its full timeout before the fix.
	if elapsed > 200*time.Millisecond {
		t.Errorf("EnrichHostnames took %v on a cancelled context, want ~0", elapsed)
	}
	for _, r := range rows {
		if r.Hostname != "" {
			t.Errorf("%s got hostname %q from a cancelled context", r.IP, r.Hostname)
		}
	}
}

// Cancelling part-way through still has to stop the remaining hosts, not just
// the first: the NetBIOS loop is serial, so one slow host must not swallow the
// rest after the operator has already asked to stop.
func TestEnrichHostnamesStopsEarly(t *testing.T) {
	rows := make([]Row, 0, 24)
	for i := 1; i <= 24; i++ {
		rows = append(rows, Row{IP: net_IPv4(i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Give the mDNS listen its full window, then cancel during the NetBIOS
	// pass — that is the shape of "Ctrl+C part-way through a sweep".
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	EnrichHostnames(ctx, rows)
	elapsed := time.Since(start)

	// 24 serial NetBIOS queries at ~900ms each would be over 20s if the cancel
	// were ignored; with it honoured the tail is cut within a read slice.
	if elapsed > 3*time.Second {
		t.Errorf("EnrichHostnames took %v for 24 rows, want the cancel to cut the tail", elapsed)
	}
}

// net_IPv4 builds a distinct documentation-range address per index (RFC 5737
// TEST-NET-1), so nothing in the test can be reached by a stray real responder.
func net_IPv4(i int) string {
	return fmt.Sprintf("192.0.2.%d", i)
}
