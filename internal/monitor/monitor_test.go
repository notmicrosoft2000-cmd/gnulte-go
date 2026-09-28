package monitor

import (
	"context"
	"testing"
	"time"

	"gnulte-go/internal/ux"
)

func TestPingOnceLocalhost(t *testing.T) {
	ctx := context.Background()
	rtt, ttl := PingOnce(ctx, "127.0.0.1", time.Second)
	if rtt < 0 {
		t.Fatalf("localhost should respond to ping, got rtt=%d (is the loopback up?)", rtt)
	}
	if ttl <= 0 {
		t.Errorf("localhost reply should carry a TTL, got ttl=%d", ttl)
	}
}

func TestStatsLossAndAvg(t *testing.T) {
	st := &Stats{Count: 2, Drops: 2, Total: 160, Min: 70, Max: 90, Last: 80}
	if st.avg() != 80 {
		t.Errorf("avg = %d, want 80", st.avg())
	}
	if loss := st.lossPct(); loss != 50.0 {
		t.Errorf("loss = %v, want 50", loss)
	}
	st2 := &Stats{}
	if loss := st2.lossPct(); loss != 0 {
		t.Error("empty stats should report 0% loss")
	}
}

func TestSparkAndStatusIcon(t *testing.T) {
	if statusIcon(-1) == "" {
		t.Error("statusIcon should never return an empty glyph")
	}
	for _, v := range []int{-1, 0, 100, 300, 500, 900} {
		if statusIcon(v) == "" {
			t.Errorf("statusIcon(%d) returned empty", v)
		}
	}
}

// The dashboard's latency history now comes from the shared block sparkline;
// this pins the mapping so a future refactor cannot silently change it.
func TestDashboardSparkMapping(t *testing.T) {
	sp := ux.SparkRTT([]int{-1, 4, 64, 300, 600}, 10)
	if sp != "·▁▅▇█" {
		t.Fatalf("SparkRTT mapping changed: %q", sp)
	}
}
