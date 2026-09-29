package tui

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GNULTE's tools each arm their own graceful SIGINT handler (signal.NotifyContext)
// *and* register a terminal-restore cleanup, so a single Ctrl+C reaches both.
// This file drives that exact arrangement in a helper subprocess, because the
// behaviour under test is a process-level race that no in-process test can see.

// runHelper re-executes this test binary as a helper of the given mode, waits
// for it to report READY, sends it `signals` interrupts, and returns what it
// printed plus its exit status.
func runHelper(t *testing.T, mode string, signals, graceMs int) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestCleanupHelper", "-test.timeout=60s")
	cmd.Env = append(os.Environ(),
		"GNULTE_CLEANUP_HELPER="+mode,
		"GNULTE_CLEANUP_HELPER_GRACE_MS="+strconv.Itoa(graceMs),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	rd := bufio.NewReader(stdout)
	var sb strings.Builder
	ready := make(chan struct{})
	go func() {
		readyOnce := false
		for {
			line, err := rd.ReadString('\n')
			sb.WriteString(line)
			if !readyOnce && strings.TrimSpace(line) == "READY" {
				readyOnce = true
				close(ready)
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("helper never became ready; got:\n%s", sb.String())
	}

	// Space the interrupts so the first one is clearly the graceful path and
	// only the extras are impatient users.
	for i := 0; i < signals; i++ {
		if i > 0 {
			time.Sleep(150 * time.Millisecond)
		}
		_ = cmd.Process.Signal(syscall.SIGINT)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var code int
	select {
	case err := <-done:
		code = cmd.ProcessState.ExitCode()
		if err != nil && code == 0 {
			code = -1
		}
	case <-time.After(25 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("helper never exited; got:\n%s", sb.String())
	}
	// Let the reader drain the tail the child wrote before exiting.
	time.Sleep(150 * time.Millisecond)
	return sb.String(), code
}

// TestCleanupHelper is the subprocess entry point. It is skipped unless one of
// the runHelper modes is requested.
func TestCleanupHelper(t *testing.T) {
	mode := os.Getenv("GNULTE_CLEANUP_HELPER")
	if mode == "" {
		t.Skip("helper process; run through runHelper")
	}
	// Shrink the safety-net grace so the timeout case does not cost 8s.
	if ms, err := strconv.Atoi(os.Getenv("GNULTE_CLEANUP_HELPER_GRACE_MS")); err == nil && ms > 0 {
		exitGrace = time.Duration(ms) * time.Millisecond
	}

	// Exactly what a tool does: restore the terminal on the way out...
	RegisterCleanup(func() { fmt.Println("CLEANUP-RAN") })

	if mode == "stuck" {
		// ...and a graceful handler that never finishes, the case the safety
		// net exists for.
		fmt.Println("READY")
		select {}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// gnulte's dashboard also switches stdin to raw input for its arrow-key
	// reader and registers that restore, so an interrupt has to put the line
	// discipline back too. Only meaningful on a real terminal, which is why
	// the PTY harness covers it end to end; here it is a bonus check.
	rawRestored := false
	if StdinTTY() {
		if restore, ok := armRawForTest(int(os.Stdin.Fd())); ok {
			RegisterCleanup(restore)
			rawRestored = true
		}
	}

	fmt.Println("READY")
	<-ctx.Done()
	// Stand-in for gnulte's real post-interrupt work: final telemetry read,
	// session teardown, the store fold, then the report decision. It is
	// deliberately slow, because that is exactly why the bug bit — a handler
	// that exits on the first signal has no trouble beating a shutdown that
	// still has I/O to do.
	time.Sleep(400 * time.Millisecond)
	if rawRestored {
		// By now the cleanup has drained, so the tty must be canonical again.
		// ICANON|ECHO are bits 1 and 3.
		if lflag, ok := rawLflag(int(os.Stdin.Fd())); ok && lflag&0o012 == 0o012 {
			fmt.Println("RAW-RESTORED")
		} else {
			fmt.Println("RAW-LEFT")
		}
	}
	fmt.Println("SHUTDOWN-COMPLETE")
	os.Exit(0)
}

// THE regression: one Ctrl+C must reach the tool's own shutdown. Before the
// fix this handler called os.Exit(130) itself, so the dashboard died mid-restore
// — no state teardown, no summary, and a shell left with no echo.
func TestInterruptLetsGracefulShutdownFinish(t *testing.T) {
	// A generous grace here: the point is that a shutdown which finishes
	// inside the window must be allowed to finish, however much I/O it has.
	out, code := runHelper(t, "graceful", 1, 5000)
	if code != 0 {
		t.Errorf("exit status = %d, want 0 (a clean shutdown, not a kill)\n%s", code, out)
	}
	if !strings.Contains(out, "SHUTDOWN-COMPLETE") {
		t.Errorf("the tool's graceful shutdown never finished:\n%s", out)
	}
	if !strings.Contains(out, "CLEANUP-RAN") {
		t.Errorf("the terminal restore never ran:\n%s", out)
	}
	if strings.Contains(out, "CLEANUP-RAN\nCLEANUP-RAN") {
		t.Errorf("the terminal restore ran twice:\n%s", out)
	}
}

// The safety net must still work: a second interrupt ends a shutdown that is
// wedged, and the terminal is restored on the way out.
func TestSecondInterruptForcesExit(t *testing.T) {
	out, code := runHelper(t, "stuck", 2, 400)
	if code != 130 {
		t.Errorf("exit status = %d, want 130 on a forced exit\n%s", code, out)
	}
	if !strings.Contains(out, "CLEANUP-RAN") {
		t.Errorf("a forced exit skipped the terminal restore:\n%s", out)
	}
}

// A single interrupt against a wedged shutdown must still end the process —
// otherwise the "safety net" would just be a way to hang gnulte forever.
func TestGraceTimeoutEndsWedgedShutdown(t *testing.T) {
	out, code := runHelper(t, "stuck", 1, 400)
	if code != 130 {
		t.Errorf("exit status = %d, want 130 after the grace period\n%s", code, out)
	}
	if !strings.Contains(out, "CLEANUP-RAN") {
		t.Errorf("the grace-period exit skipped the terminal restore:\n%s", out)
	}
}
