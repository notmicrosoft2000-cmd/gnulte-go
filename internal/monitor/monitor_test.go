package monitor

import (
	"context"
	"testing"
)

func TestPingOnceLocalhost(t *testing.T) {
	ctx := context.Background()
	rtt := PingOnce(ctx, "127.0.0.1")
	if rtt < 0 {
		t.Fatalf("localhost should respond to ping, got rtt=%d (is the loopback up?)", rtt)
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

func TestSparkAndStatusChar(t *testing.T) {
	if sparkChar(-1) != 'x' || sparkChar(40) != '.' || sparkChar(1000) != '#' {
		t.Error("sparkChar mapping wrong")
	}
	if statusDot(-1) != 'x' || statusDot(150) != 'o' || statusDot(500) != '~' || statusDot(999) != '!' {
		t.Error("statusDot mapping wrong")
	}
}
