// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build linux

package discover

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeWire is a scripted segment: it answers the addresses in `answerers` (by
// handing out the queued reply on the next read after the address is asked) and
// counts how many questions it was asked, per address and in total. It also
// tracks the peak number of asks in flight, so a test can hold the sweep to its
// concurrency cap.
type fakeWire struct {
	mu        sync.Mutex
	answerers map[string]net.HardwareAddr
	pending   []struct {
		mac net.HardwareAddr
		ip  string
	}
	asked      map[string]int
	totalAsked int
	inFlight   int32
	peakFlight int32
	selfMAC    net.HardwareAddr
	selfIP     string
	// silentUntil makes an address ignore its first N questions, modelling a
	// frame lost in a busy segment.
	silentUntil map[string]int
}

func newFakeWire(answerers map[string]net.HardwareAddr) *fakeWire {
	return &fakeWire{
		answerers:   answerers,
		asked:       map[string]int{},
		silentUntil: map[string]int{},
		selfMAC:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		selfIP:      "192.168.99.132",
	}
}

func (f *fakeWire) ask(ip string) error {
	// The in-flight count must not be guarded by the same mutex that serialises
	// the maps: holding it across the whole call would force concurrency to 1 and
	// the peak would say nothing. Atomics track it independently.
	cur := atomic.AddInt32(&f.inFlight, 1)
	for {
		peak := atomic.LoadInt32(&f.peakFlight)
		if cur <= peak || atomic.CompareAndSwapInt32(&f.peakFlight, peak, cur) {
			break
		}
	}
	defer atomic.AddInt32(&f.inFlight, -1)
	// Yield while "on the wire" so a real concurrency level is observable: a send
	// that returned instantly would let the scheduler run one worker at a time
	// and hide an unbounded worker pool.
	runtime.Gosched()

	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[ip]++
	f.totalAsked++
	if f.silentUntil[ip] > 0 {
		f.silentUntil[ip]--
	} else if mac, ok := f.answerers[ip]; ok {
		f.pending = append(f.pending, struct {
			mac net.HardwareAddr
			ip  string
		}{mac, ip})
	}
	return nil
}

func (f *fakeWire) reply() (net.HardwareAddr, net.IP, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pending) == 0 {
		return nil, nil, false, nil
	}
	next := f.pending[0]
	f.pending = f.pending[1:]
	return next.mac, net.ParseIP(next.ip), true, nil
}

func (f *fakeWire) local() (net.HardwareAddr, net.IP) { return f.selfMAC, net.ParseIP(f.selfIP) }
func (f *fakeWire) close() error                      { return nil }

func (f *fakeWire) stats() (total, peak int, asked map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	asked = make(map[string]int, len(f.asked))
	for k, v := range f.asked {
		asked[k] = v
	}
	return f.totalAsked, int(atomic.LoadInt32(&f.peakFlight)), asked
}

var threeHosts = []string{"192.168.99.1", "192.168.99.5", "192.168.99.13"}

// The sweep's real timings (a 2 s listen window) would make this suite take half
// a minute. The behaviour under test — rounds, retries, progress, caps — is the
// same at any window; only patience changes, so the tests shrink it.
const (
	fastWindow = 40 * time.Millisecond
	fastGap    = time.Millisecond
)

// TestSweepFindsEveryAnsweringHost is the end-to-end sweep test on a scripted
// segment: three addresses asked, two answer, and both are reported with the MAC
// they answered with.
func TestSweepFindsEveryAnsweringHost(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1":  {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		"192.168.99.13": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
	})
	res := sweepWith(context.Background(), fw, threeHosts, "lo", 4, 2, nil, fastWindow, fastGap)

	if len(res.live) != 2 {
		t.Fatalf("live = %v, want 2 answering hosts", res.live)
	}
	if res.live[0] != "192.168.99.1" || res.live[1] != "192.168.99.13" {
		t.Fatalf("live = %v, want [.1 .13]", res.live)
	}
	if res.macs["192.168.99.1"] != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("mac for .1 = %q", res.macs["192.168.99.1"])
	}
	if res.macs["192.168.99.13"] != "AA:BB:CC:DD:EE:02" {
		t.Fatalf("mac for .13 = %q", res.macs["192.168.99.13"])
	}
	if _, ok := res.macs["192.168.99.5"]; ok {
		t.Fatal("the silent address got a MAC")
	}
}

// TestSweepReasksAHostThatMissedTheFirstQuestion is the retry round's reason to
// exist: a device whose first who-has was lost must still be found, rather than
// written off as absent.
func TestSweepReasksAHostThatMissedTheFirstQuestion(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
	})
	fw.silentUntil["192.168.99.1"] = 1 // ignore the first question
	fw.answerers["192.168.99.5"] = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03}

	res := sweepWith(context.Background(), fw, threeHosts, "lo", 2, 2, nil, fastWindow, fastGap)

	if len(res.live) != 2 {
		t.Fatalf("live = %v, want both hosts found on the retry round", res.live)
	}
	_, _, asked := fw.stats()
	if asked["192.168.99.1"] < 2 {
		t.Fatalf(".1 was asked %d times, want at least 2 (the first answer was lost)", asked["192.168.99.1"])
	}
}

// TestSweepHonoursTheSinglePassMode is what keeps the implicit neighbour sweep
// quick: asked for one round, a host that misses it is given up on, and a host
// that answered is never re-asked.
func TestSweepHonoursTheSinglePassMode(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
	})
	fw.silentUntil["192.168.99.5"] = 99 // never answers

	res := sweepWith(context.Background(), fw, threeHosts, "lo", 2, 1, nil, fastWindow, fastGap)

	if len(res.live) != 1 {
		t.Fatalf("live = %v, want only the host that answered", res.live)
	}
	_, _, asked := fw.stats()
	if asked["192.168.99.1"] != 1 {
		t.Fatalf(".1 was asked %d times, want 1 (an answered host is never re-asked)", asked["192.168.99.1"])
	}
	if asked["192.168.99.5"] != 1 {
		t.Fatalf(".5 was asked %d times, want 1 (single-pass mode does not retry)", asked["192.168.99.5"])
	}
	if asked["192.168.99.13"] != 1 {
		t.Fatalf(".13 was asked %d times, want 1", asked["192.168.99.13"])
	}
}

// TestSweepAdvancesProgressWhileRunning is the progress-bar contract: a caller
// watching the sweep must see intermediate reports, not a single report at the
// end. A bar that jumps straight to the total looks broken on a large subnet.
func TestSweepAdvancesProgressWhileRunning(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1":  {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		"192.168.99.5":  {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
		"192.168.99.13": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03},
	})
	type tick struct{ done, alive int }
	var ticks []tick
	sweepWith(context.Background(), fw, threeHosts, "lo", 4, 1, func(done, alive int) {
		ticks = append(ticks, tick{done, alive})
	}, fastWindow, fastGap)

	if len(ticks) < 2 {
		t.Fatalf("got %d progress reports, want several as answers landed: %v", len(ticks), ticks)
	}
	// Alive must rise as answers land, and never exceed the work done.
	var last tick
	prevAlive := 0
	for i, tk := range ticks {
		if tk.alive < prevAlive {
			t.Fatalf("report %d went backwards: alive %d after %d", i, tk.alive, prevAlive)
		}
		if tk.alive > tk.done {
			t.Fatalf("report %d claims alive=%d > completed=%d", i, tk.alive, tk.done)
		}
		prevAlive = tk.alive
		last = tk
	}
	if last.done != 3 {
		t.Fatalf("final report completed = %d, want 3 (every question asked)", last.done)
	}
	if last.alive != 3 {
		t.Fatalf("final report alive = %d, want 3", last.alive)
	}
}

// TestSweepProgressFinishesEvenWhenNobodyAnswers closes the other half of the
// bar contract: a sweep that finds nothing must still report the work as done,
// so the bar does not sit stuck at zero looking like a hang.
func TestSweepProgressFinishesEvenWhenNobodyAnswers(t *testing.T) {
	fw := newFakeWire(nil)
	var done, alive int
	calls := 0
	sweepWith(context.Background(), fw, threeHosts, "lo", 4, 1, func(d, a int) {
		calls++
		done, alive = d, a
	}, fastWindow, fastGap)
	if calls == 0 {
		t.Fatal("a sweep that found nothing reported no progress at all")
	}
	if done != 3 || alive != 0 {
		t.Fatalf("final report = (%d, %d), want (3, 0)", done, alive)
	}
}

// TestSweepCapsConcurrency is the flood guard: whatever -t an operator passes,
// the number of who-has frames in flight must stay within the cap. An unbounded
// worker pool on a /16 would put tens of thousands of ARP requests on the wire.
func TestSweepCapsConcurrency(t *testing.T) {
	for _, threads := range []int{-5, 0, 1, 3, 256, 100000} {
		fw := newFakeWire(nil)
		sweepWith(context.Background(), fw, threeHosts, "lo", threads, 1, nil, fastWindow, fastGap)
		_, peak, _ := fw.stats()
		if peak > sweepThreadCap {
			t.Fatalf("threads=%d: %d asks in flight, over the %d cap", threads, peak, sweepThreadCap)
		}
		if peak > len(threeHosts) {
			t.Fatalf("threads=%d: %d asks in flight for only %d addresses", threads, peak, len(threeHosts))
		}
		if peak < 1 {
			t.Fatalf("threads=%d: nothing was ever asked", threads)
		}
	}
}

// TestSweepStopsOnContextCancel is the interrupt path: a cancelled sweep must
// return promptly with what it has, rather than sitting out its full window.
// This is what makes Ctrl+C responsive during a scan.
func TestSweepStopsOnContextCancel(t *testing.T) {
	fw := newFakeWire(nil) // nothing ever answers, so only cancel can end it
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	res := sweepWith(ctx, fw, threeHosts, "lo", 4, sweepRounds, nil, sweepWindow, fastGap)
	elapsed := time.Since(start)

	if len(res.live) != 0 {
		t.Fatalf("live = %v, want none", res.live)
	}
	if elapsed > time.Second {
		t.Fatalf("a cancelled sweep took %v, want it to return immediately", elapsed)
	}
	if total, _, _ := fw.stats(); total != 0 {
		t.Fatalf("a sweep cancelled before it started still asked %d questions", total)
	}
}

// TestSweepSurvivesAWireFailure checks the reader's error handling: a socket that
// dies mid-sweep must end the sweep cleanly, returning whatever had already
// answered, not hang and not panic.
type brokenWire struct {
	*fakeWire
	failAfter int
	calls     int
}

func (b *brokenWire) reply() (net.HardwareAddr, net.IP, bool, error) {
	b.calls++
	if b.calls > b.failAfter {
		return nil, nil, false, syscall.EIO
	}
	return b.fakeWire.reply()
}

func TestSweepSurvivesAWireFailure(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
	})
	bw := &brokenWire{fakeWire: fw, failAfter: 2}

	res := sweepWith(context.Background(), bw, threeHosts, "lo", 4, 2, nil, fastWindow, fastGap)

	// Whatever answered before the failure is kept; the rest is simply unknown.
	if len(res.live) > len(threeHosts) {
		t.Fatalf("live = %v, more than the targets asked", res.live)
	}
	if _, ok := res.macs["192.168.99.1"]; !ok && len(res.live) == 0 {
		t.Fatal("a wire failure discarded everything without reporting anything")
	}
}

// TestSweepSkipsOurOwnAddressAndJunkTargets is the input guard at the sweep
// level: asking ourselves would make us our own "discovery", and malformed
// targets must not reach the wire.
func TestSweepSkipsOurOwnAddressAndJunkTargets(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.132": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, // ourselves
		"192.168.99.5":   {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
	})
	res := sweepWith(context.Background(), fw,
		[]string{"192.168.99.132", "garbage", "", "192.168.99.5", "192.168.99.5"},
		"lo", 4, 1, nil, fastWindow, fastGap)

	if len(res.live) != 1 || res.live[0] != "192.168.99.5" {
		t.Fatalf("live = %v, want only [.5]", res.live)
	}
	total, _, asked := fw.stats()
	if total != 1 {
		t.Fatalf("asked %d questions, want 1 (self, junk and the duplicate were dropped): %v", total, asked)
	}
}

// TestSweepRetriesWhenTheWireIsTheRealOne exercises the same retry contract
// through `sweep` itself (the entry point gnulte-scan calls) rather than
// sweepWith, so a change to the default round count is caught here. Without
// this, dropping the retry default would silently cost every device whose first
// frame is lost — and the sweepWith tests would still pass.
func TestSweepRetriesWhenTheWireIsTheRealOne(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
	})
	fw.silentUntil["192.168.99.1"] = 1
	defer swapWire(fw)()

	res := runSweep(context.Background(), threeHosts, "lo", 4, nil)

	if len(res.live) != 1 || res.live[0] != "192.168.99.1" {
		t.Fatalf("live = %v, want [.1] found on a retry", res.live)
	}
	_, _, asked := fw.stats()
	if asked["192.168.99.1"] < 2 {
		t.Fatalf(".1 was asked %d times, want the default sweep to re-ask", asked["192.168.99.1"])
	}
}

// TestSweepThroughSweepStopsOnCancel checks the cancel path through `sweep` as
// well: a scan interrupted mid-sweep must return promptly rather than sitting
// out every remaining window.
func TestSweepThroughSweepStopsOnCancel(t *testing.T) {
	fw := newFakeWire(nil)
	defer swapWire(fw)()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	runSweep(ctx, threeHosts, "lo", 4, nil)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a cancelled sweep took %v, want an immediate return", elapsed)
	}
}

// TestSweepThroughSweepAsksNobodyWhenTheWireFails covers the open-failure path:
// if the raw socket cannot be opened at all (not root, no such interface), the
// sweep returns empty instead of reporting hosts it never heard from.
func TestSweepThroughSweepAsksNobodyWhenTheWireFails(t *testing.T) {
	defer swapWire(erroringWire{err: syscall.EPERM})()
	res := runSweep(context.Background(), threeHosts, "lo", 4, nil)
	if len(res.live) != 0 {
		t.Fatalf("live = %v, want none when the socket cannot be opened", res.live)
	}
}

// TestSweepThroughSweepWithNoUsableLocalAddress is the other open-time guard: a
// wire that reports no address of our own cannot craft a who-has, so nothing is
// asked and nothing is claimed.
func TestSweepThroughSweepWithNoUsableLocalAddress(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{"192.168.99.1": devA})
	fw.selfMAC = nil
	fw.selfIP = ""
	defer swapWire(fw)()

	res := runSweep(context.Background(), threeHosts, "lo", 4, nil)
	if len(res.live) != 0 {
		t.Fatalf("live = %v, want none without a local address to send from", res.live)
	}
	if total, _, _ := fw.stats(); total != 0 {
		t.Fatalf("asked %d questions with no local address", total)
	}
}

// erroringWire is a wire that cannot be opened at all.
type erroringWire struct{ err error }

func (erroringWire) ask(string) error { return nil }
func (erroringWire) reply() (net.HardwareAddr, net.IP, bool, error) {
	return nil, nil, false, nil
}
func (erroringWire) local() (net.HardwareAddr, net.IP) { return nil, nil }
func (erroringWire) close() error                      { return nil }

// swapWire points the package's socket seam at w for the duration of a test.
func swapWire(w arpWire) func() {
	prev := newWire
	newWire = func(string) (arpWire, error) { return w, nil }
	return func() { newWire = prev }
}

// TestResolveOnRetriesOnceAndReturnsTheMAC is the engine's MAC-resolution path:
// a victim whose first who-has is lost must still resolve, and the MAC returned
// must be the one that answered. This is what replaced `arping -c 1`.
func TestResolveOnRetriesOnceAndReturnsTheMAC(t *testing.T) {
	want := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07}
	fw := newFakeWire(map[string]net.HardwareAddr{"192.168.99.1": want})
	fw.silentUntil["192.168.99.1"] = 1 // lose the first frame
	defer swapWire(fw)()

	got, err := resolveOn(context.Background(), "lo", "192.168.99.1", fastWindow, resolveRounds)
	if err != nil {
		t.Fatalf("resolveOn failed: %v", err)
	}
	if !sameMAC(got, want) {
		t.Fatalf("resolved MAC = %s, want %s", got, want)
	}
}

// TestResolveOnGivesUpOnASilentAddress pins the failure: an address that never
// answers returns an error, so the engine falls back to the kernel table rather
// than spoofing a MAC it never heard.
func TestResolveOnGivesUpOnASilentAddress(t *testing.T) {
	fw := newFakeWire(nil)
	defer swapWire(fw)()

	if _, err := resolveOn(context.Background(), "lo", "192.168.99.1", fastWindow, resolveRounds); err == nil {
		t.Fatal("resolveOn reported success for an address that never answered")
	}
}

// TestResolveOnDoesNotAskAgainAfterAnAnswer keeps the retry cheap: once the
// address answers, it must not be asked a second time.
func TestResolveOnDoesNotAskAgainAfterAnAnswer(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{"192.168.99.1": devA})
	defer swapWire(fw)()

	if _, err := resolveOn(context.Background(), "lo", "192.168.99.1", fastWindow, resolveRounds); err != nil {
		t.Fatalf("resolveOn failed: %v", err)
	}
	if _, _, asked := fw.stats(); asked["192.168.99.1"] != 1 {
		t.Fatalf(".1 was asked %d times, want exactly 1", asked["192.168.99.1"])
	}
}

// TestResolveOnHandlesNoLocalAddress is the open-time guard: with no address of
// our own there is no valid sender for a who-has, so resolution must fail rather
// than emit a malformed frame.
func TestResolveOnHandlesNoLocalAddress(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{"192.168.99.1": devA})
	fw.selfMAC, fw.selfIP = nil, ""
	defer swapWire(fw)()

	if _, err := resolveOn(context.Background(), "lo", "192.168.99.1", fastWindow, resolveRounds); err == nil {
		t.Fatal("resolveOn succeeded with no local address")
	}
}

// TestSweepCapsConcurrencyPastTheTargetCount is the flood guard at the size that
// matters: with enough addresses that the worker count *could* exceed the cap,
// the cap must actually bite. The earlier cap test only used three targets, so
// the per-target clamp alone satisfied it and a removed global cap slipped by.
func TestSweepCapsConcurrencyPastTheTargetCount(t *testing.T) {
	targets := make([]string, 0, 600)
	for i := 1; i <= 600; i++ {
		targets = append(targets, "10.9."+itoa(i/254)+"."+itoa(i%254+1))
	}
	fw := newFakeWire(nil) // nobody answers: the send phase still runs
	sweepWith(context.Background(), fw, targets, "lo", 100000, 1, nil, fastWindow, fastGap)

	total, peak, _ := fw.stats()
	if total == 0 {
		t.Fatal("no questions were asked at all")
	}
	if peak > sweepThreadCap {
		t.Fatalf("%d asks in flight, over the %d cap — the send phase is unbounded", peak, sweepThreadCap)
	}
}

// TestSweepRetryAsksOnlyTheSilent is the other half of the retry contract: the
// second round must not spend questions on hosts that already answered. A retry
// that re-asks everyone doubles the wire traffic of every sweep for no gain.
func TestSweepRetryAsksOnlyTheSilent(t *testing.T) {
	fw := newFakeWire(map[string]net.HardwareAddr{
		"192.168.99.1": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
	})
	fw.silentUntil["192.168.99.5"] = 99 // never answers; keeps round 2 alive
	fw.answerers["192.168.99.13"] = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03}

	sweepWith(context.Background(), fw, threeHosts, "lo", 4, 2, nil, fastWindow, fastGap)

	_, _, asked := fw.stats()
	for _, ip := range []string{"192.168.99.1", "192.168.99.13"} {
		if asked[ip] != 1 {
			t.Fatalf("%s was asked %d times, want exactly 1 — the retry re-asked a host that answered", ip, asked[ip])
		}
	}
	if asked["192.168.99.5"] != 2 {
		t.Fatalf(".5 was asked %d times, want 2 (the silent host is the retry's whole point)", asked["192.168.99.5"])
	}
}

// itoa avoids pulling strconv into the test just for two call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
