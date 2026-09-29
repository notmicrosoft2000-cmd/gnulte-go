package monitor

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPrintHeaderIncludesLabel: --note decorates the console header and, via
// the session log, the HTML report.
func TestPrintHeaderIncludesLabel(t *testing.T) {
	m := &Monitor{
		Targets:    []string{"10.0.0.1"},
		Label:      "gaming-test-3",
		Impairment: "latency 50ms",
		Iface:      "wlan0",
		Interval:   time.Second,
		Start:      time.Now(),
	}
	m.printHeader()
	joined := strings.Join(m.Log, "\n")
	if !strings.Contains(joined, "note        gaming-test-3") {
		t.Fatalf("header log missing the note line:\n%s", joined)
	}
	// With no label the header must not grow a blank "note" row.
	m2 := &Monitor{Targets: []string{"10.0.0.1"}, Interval: time.Second}
	m2.printHeader()
	if strings.Contains(strings.Join(m2.Log, "\n"), "note  ") {
		t.Fatalf("empty label should not print a note line:\n%s", strings.Join(m2.Log, "\n"))
	}
}

// TestDashboardSessionFooter: the live dashboard footer carries the running
// session totals and the netem reading filed by an OnTick hook, each labelled
// exactly once.
func TestDashboardSessionFooter(t *testing.T) {
	m := &Monitor{
		Targets:  []string{"10.0.0.1", "10.0.0.2"},
		Interval: time.Second,
		Start:    time.Now().Add(-7 * time.Second),
		Label:    "gaming-test-3",
	}
	metrics := "delayed 4 · reordered 1 · dropped 0 · backlog 0p · delay 12ms"
	m.SetNetem(metrics)
	stats := []*Stats{{}, {}}
	notes := []string{"", ""}

	// renderDashboard paints to stdout (or the alternate-screen frame);
	// capture it so the footer text is actually asserted, not assumed.
	out := captureStdout(t, func() {
		m.renderDashboard(stats, notes, false, false)
	})
	if !strings.Contains(out, "session 7s · 2 host(s) · 0 ok · 0 lost (0%)") {
		t.Fatalf("session totals line missing or wrong:\n%s", out)
	}
	if !strings.Contains(out, "netem live · "+metrics) {
		t.Fatalf("netem footer line missing:\n%s", out)
	}
	if n := strings.Count(out, "netem live ·"); n != 1 {
		t.Fatalf("netem label rendered %d times, want 1:\n%s", n, out)
	}
	// The elapsed clock must tick with the session, not stay at "…".
	m.Start = time.Time{}
	if again := captureStdout(t, func() {
		m.renderDashboard(stats, notes, false, false)
	}); !strings.Contains(again, "session … ·") {
		t.Fatalf("zero Start should render the placeholder, got:\n%s", again)
	}
	// No telemetry filed yet means no netem line at all.
	m.SetNetem("")
	if bare := captureStdout(t, func() {
		m.renderDashboard(stats, notes, false, false)
	}); strings.Contains(bare, "netem") {
		t.Fatalf("netem footer shown with no telemetry:\n%s", bare)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// was written, so the console painters can be asserted on directly.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = saved
	w.Close()
	out := <-done
	r.Close()
	return stripANSI(out)
}

// stripANSI removes colour/cursor escapes so assertions match the plain text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && !isANSITerminator(s[i]) {
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isANSITerminator(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// TestSetNetemLastWriteWins: the footer always shows the newest telemetry, and
// an empty line clears it.
func TestSetNetemLastWriteWins(t *testing.T) {
	m := &Monitor{}
	if m.netem != "" {
		t.Fatalf("fresh monitor should have no telemetry, got %q", m.netem)
	}
	m.SetNetem("first")
	m.SetNetem("second")
	if m.netem != "second" {
		t.Fatalf("netem = %q, want the latest write", m.netem)
	}
	m.SetNetem("")
	if m.netem != "" {
		t.Fatalf("empty write should clear the footer, got %q", m.netem)
	}
}
