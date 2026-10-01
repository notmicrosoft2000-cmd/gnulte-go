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
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/arpspoof"
)

// arpWire is the one thing the sweep needs from the network: a way to ask an
// address who it is, and a way to take one thing off the receive queue. The real
// implementation is a raw AF_PACKET socket; the interface exists so the sweep's
// own logic — how many rounds, how much listening, what a progress bar is told —
// is testable without root or a live segment.
type arpWire interface {
	// ask puts one who-has for ip on the wire.
	ask(ip string) error
	// reply takes the next pending answer, returning ok=false when nothing is
	// waiting. err is non-nil only for a real socket failure.
	reply() (mac net.HardwareAddr, ip net.IP, ok bool, err error)
	// local identifies us, so a sweep can ignore its own echo.
	local() (net.HardwareAddr, net.IP)
	close() error
}

// socketWire adapts a raw ARP socket to arpWire.
type socketWire struct {
	sp       *arpspoof.Spoofer
	localIP  net.IP
	localMAC net.HardwareAddr
}

func newSocketWire(iface string) (arpWire, error) {
	sp, err := arpspoof.Open(iface)
	if err != nil {
		return nil, err
	}
	return &socketWire{sp: sp, localIP: sp.LocalIP(), localMAC: sp.LocalMAC()}, nil
}

func (w *socketWire) ask(ip string) error {
	target := net.ParseIP(ip)
	if target == nil || target.To4() == nil {
		return nil
	}
	return w.sp.SendRaw(arpspoof.BuildARPRequest(w.localMAC, w.localIP, target.To4()))
}

func (w *socketWire) reply() (net.HardwareAddr, net.IP, bool, error) {
	mac, ip, _, ok, err := w.sp.ReadReply()
	return mac, ip, ok, err
}

func (w *socketWire) local() (net.HardwareAddr, net.IP) { return w.localMAC, w.localIP }

func (w *socketWire) close() error { return w.sp.Close() }

// runSweep puts the sweep on the wire: ask every target, listen for answers,
// re-ask whatever stayed quiet, then report what answered.
//
// The send side is bounded by `threads` concurrent senders. The receive side is
// a single reader, because one AF_PACKET socket has one receive queue and every
// answer is matched against the whole set regardless of who asked. A caller
// passing an absurd -t gets the cap rather than a segment-flooding default.
func runSweep(ctx context.Context, targets []string, iface string, threads int, report func(completed, alive int)) sweepResult {
	return sweep(ctx, targets, iface, threads, sweepRounds, report)
}

// newWire is the seam between the sweep and a real socket: production always uses
// newSocketWire, and tests substitute a scripted segment so the sweep's own
// behaviour (rounds, retries, progress, caps) is exercised without root.
var newWire func(iface string) (arpWire, error) = newSocketWire

// sweep is runSweep's body, with the asking rounds made explicit: an explicit
// `gnulte-scan --arp` gets retries (a dropped frame should not cost a device),
// while the implicit sweep inside a neighbour lookup gets one pass, because that
// lookup is not the user's reason for running and must stay quick.
func sweep(ctx context.Context, targets []string, iface string, threads, rounds int, report func(completed, alive int)) sweepResult {
	w, err := newWire(iface)
	if err != nil {
		return sweepResult{}
	}
	defer w.close()
	return sweepWith(ctx, w, targets, iface, threads, rounds, report, sweepWindow, sweepRetryGap)
}

// sweepWith is the sweep proper, independent of the socket. `iface` is only used
// to look up a MAC the wire did not give us; window and gap are the how long to
// listen and how long to pause between asking rounds, passed in so the timing can
// be exercised without the test suite waiting out real windows.
func sweepWith(ctx context.Context, w arpWire, targets []string, iface string, threads, rounds int, report func(completed, alive int), window, gap time.Duration) sweepResult {
	if threads < 1 {
		threads = 1
	}
	if threads > sweepThreadCap {
		threads = sweepThreadCap
	}
	if rounds < 1 {
		rounds = 1
	}
	if rounds > sweepRounds {
		rounds = sweepRounds
	}

	localMAC, localIP := w.local()
	if len(localMAC) != 6 || localIP == nil {
		return sweepResult{}
	}
	ps := newProbeSet(targets, localMAC, localIP.String())
	if len(ps.order) == 0 {
		return sweepResult{}
	}

	// asked counts questions put on the wire so far, so a progress bar advances
	// by work done rather than by hosts found — otherwise a sweep that finds
	// nothing still looks finished.
	asked := 0
	for round := 0; round < rounds; round++ {
		todo := ps.pending()
		if len(todo) == 0 || ctx.Err() != nil {
			break
		}
		askAll(w, todo, threads)
		asked += len(todo)
		waitForAnswers(ctx, w, ps, window, report, func() (int, int) {
			done := asked
			if total := len(ps.order); done > total {
				done = total
			}
			return done, ps.live()
		})
		if round+1 < rounds && len(ps.pending()) > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(gap):
			}
		}
	}
	if report != nil {
		// Finish the bar where the caller expects it: one tick per address
		// asked about, however many answered. Re-asking a silent address must
		// not push the bar past its own total.
		report(len(ps.order), ps.live())
	}
	return ps.collect(iface)
}

// askAll sends one who-has per address, threads at a time. A send failure is not
// fatal: one unreachable address must not abandon the rest of the questions.
func askAll(w arpWire, todo []string, threads int) {
	if threads > len(todo) {
		threads = len(todo)
	}
	jobs := make(chan string, len(todo))
	for _, ip := range todo {
		jobs <- ip
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				_ = w.ask(ip)
			}
		}()
	}
	wg.Wait()
}

// waitForAnswers drains replies until the window expires, the context ends, every
// target has answered, or the wire itself fails. Progress is reported as answers
// land so a bar tracks discoveries while the sweep runs.
func waitForAnswers(ctx context.Context, w arpWire, ps *probeSet, window time.Duration, report func(int, int), counts func() (int, int)) {
	deadline := time.Now().Add(window)
	reported := 0
	for {
		fromMAC, fromIP, _, err := w.reply()
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// EAGAIN arrives as a non-error with ok=false, so a real error here
			// means no more answers are coming (interface gone, socket closed).
			return
		}
		// note declines replies that must not be credited (our own echo, a
		// stranger, a repeat), so it is safe to hand it everything the shared
		// ARP socket surfaced.
		ps.note(fromMAC, fromIP)
		if n := ps.live(); n > reported {
			reported = n
			if report != nil && counts != nil {
				done, alive := counts()
				report(done, alive)
			}
		}
		if ps.settled() {
			return
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sweepIdle):
		}
	}
}

// resolveOne asks a single address who it is, over the same raw socket the
// sweep uses. It re-asks once, because a dropped first frame should not decide
// whether a victim's MAC resolves.
func resolveOne(ctx context.Context, iface, ip string) (net.HardwareAddr, error) {
	return resolveOn(ctx, iface, ip, resolveWindow, resolveRounds)
}

// resolveOn is resolveOne with its patience exposed, so the retry contract can be
// tested without waiting out real windows.
func resolveOn(ctx context.Context, iface, ip string, window time.Duration, rounds int) (net.HardwareAddr, error) {
	w, err := newWire(iface)
	if err != nil {
		return nil, err
	}
	defer w.close()

	localMAC, localIP := w.local()
	if len(localMAC) != 6 || localIP == nil {
		return nil, errors.New("interface has no usable IPv4/MAC")
	}
	target := net.ParseIP(ip)
	if target == nil || target.To4() == nil {
		return nil, errors.New("not an IPv4 address: " + ip)
	}
	ps := newProbeSet([]string{ip}, localMAC, localIP.String())
	if len(ps.order) == 0 {
		return nil, errors.New("cannot resolve own address: " + ip)
	}

	var found net.HardwareAddr
	for round := 0; round < rounds && found == nil; round++ {
		if err := w.ask(ip); err != nil {
			return nil, err
		}
		waitForAnswers(ctx, w, ps, window, nil, nil)
		if p := ps.probes[target.To4().String()]; p.answered {
			found = p.mac
		}
	}
	if found != nil {
		return found, nil
	}
	return nil, errors.New("no ARP answer from " + ip)
}
