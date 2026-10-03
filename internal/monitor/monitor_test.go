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

// The session transcript gains a line per sample per target and was never
// trimmed: a day at the default 1s interval is ~86k lines per target, all of
// which the HTML report embeds. The cap keeps the tail.
func TestRecTrimsLogToCap(t *testing.T) {
	m := &Monitor{}
	total := maxLogLines + 500
	for i := 0; i < total; i++ {
		m.rec("line")
	}
	if len(m.Log) != maxLogLines {
		t.Errorf("Log length = %d, want capped at %d", len(m.Log), maxLogLines)
	}
	// The cap drops from the head, keeping the newest.
	m.rec("newest")
	if m.Log[len(m.Log)-1] != "newest" {
		t.Errorf("last line = %q, want %q", m.Log[len(m.Log)-1], "newest")
	}
}

// trimHistory bounds the latency samples and the loss strip together; if the
// loss series is not trimmed in lock-step the dashboard's loss strip and the
// run-length rollup grow without limit over a long session.
func TestTrimHistoryTrimsSamplesAndLossTogether(t *testing.T) {
	m := &Monitor{History: 3}
	st := &Stats{
		Samples:    []int{1, 2, 3, 4, 5},
		LossSeries: []int{0, 100, 0, 100, 100},
	}
	m.trimHistory(st)
	if len(st.Samples) != 3 || st.Samples[0] != 3 || st.Samples[2] != 5 {
		t.Errorf("samples = %v, want the tail [3 4 5]", st.Samples)
	}
	if len(st.LossSeries) != 3 || st.LossSeries[0] != 0 || st.LossSeries[2] != 100 {
		t.Errorf("loss series = %v, want the tail [0 100 100]", st.LossSeries)
	}
	// History 0 disables trimming entirely.
	m2 := &Monitor{}
	st2 := &Stats{Samples: []int{1, 2}, LossSeries: []int{0, 0}}
	m2.trimHistory(st2)
	if len(st2.Samples) != 2 || len(st2.LossSeries) != 2 {
		t.Errorf("History=0 should not trim: %v / %v", st2.Samples, st2.LossSeries)
	}
}

// publish hands the report a deep copy; if the loss series were not copied the
// live sampler would keep mutating the slice the report reads.
func TestPublishCopiesLossSeries(t *testing.T) {
	m := &Monitor{}
	st := &Stats{Samples: []int{1, 2}, LossSeries: []int{0, 100}, Count: 1, Drops: 1}
	m.publish("10.0.0.1", st)
	if len(m.Results) != 1 {
		t.Fatalf("results = %v", m.Results)
	}
	if got := m.Results[0].Stats.LossSeries; len(got) != 2 || got[1] != 100 {
		t.Fatalf("published loss series = %v", got)
	}
	st.LossSeries[0] = 77
	st.Samples[0] = 88
	if m.Results[0].Stats.LossSeries[0] != 0 || m.Results[0].Stats.Samples[0] != 1 {
		t.Fatal("publish aliased the source slices")
	}
}
