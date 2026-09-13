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
// untouched, and tcpdump capture.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

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
	for _, bin := range []string{"arpspoof", "tc", "ping"} {
		if _, err := exec.LookPath(bin); err != nil {
			problems = append(problems, fmt.Sprintf("missing required command: %s", bin))
		}
	}
	if c.CaptureFile != "" && c.CaptureFile != "-" {
		if _, err := exec.LookPath("tcpdump"); err != nil {
			problems = append(problems, "missing required command: tcpdump (for --capture)")
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

// captureArgs builds the tcpdump arguments (host <target> … -w <file>).
func captureArgs(c *Config, iface string) []string {
	args := []string{"-i", iface}
	for _, t := range c.Targets {
		args = append(args, "host", t)
	}
	if c.CaptureFile == "-" {
		args = append(args, "-")
	} else {
		args = append(args, "-w", c.CaptureFile)
	}
	return args
}

func readForward() (string, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeForward(v string) error {
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
	qdiscApplied   bool
	restoreErr     []string
	capture        *exec.Cmd
	captureWait    chan struct{}
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

	s := &Session{cfg: cfg, captureWait: make(chan struct{})}
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
// process group, so a Ctrl+C on the session does not kill the restore.
func runRoot(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Run()
}

func (s *Session) startCapture(ctx context.Context) error {
	// Overwrite guard (mirrors Bash behaviour).
	if s.cfg.CaptureFile != "-" {
		if fi, err := os.Stat(s.cfg.CaptureFile); err == nil && fi.Mode().IsRegular() {
			return fmt.Errorf("capture file %s already exists (move it or delete it first)", s.cfg.CaptureFile)
		}
	}
	cmd := exec.CommandContext(ctx, "tcpdump", captureArgs(&s.cfg, s.cfg.Interface)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if s.cfg.CaptureFile == "-" {
		cmd.Stdout = os.Stdout
	} else {
		cmd.Stdout = nil
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tcpdump failed to start: %w", err)
	}
	s.capture = cmd
	s.captureWait = make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(s.captureWait)
	}()
	// Give tcpdump a moment and verify it is alive.
	time.Sleep(time.Second)
	if s.capture.Process != nil && s.capture.Process.Signal(syscall.Signal(0)) != nil {
		s.stopCapture()
		return errors.New("tcpdump exited immediately (wrong interface or permission)")
	}
	return nil
}

func (s *Session) startSpoofs(ctx context.Context) error {
	for _, t := range s.cfg.Targets {
		// target -> we are the gateway
		c1 := exec.CommandContext(ctx, "arpspoof", "-i", s.cfg.Interface, "-t", t, s.cfg.Gateway)
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
	_, _ = c.Process.Wait()
}

func (s *Session) applyTC(ctx context.Context) error {
	before, err := exec.Command("tc", "qdisc", "show", "dev", s.cfg.Interface).CombinedOutput()
	if err == nil {
		lines := strings.SplitN(string(before), "\n", 2)
		if len(lines) > 0 {
			s.qdiscBefore = strings.TrimSpace(lines[0])
		}
	}
	// Deleting the current root qdisc is best-effort (none may exist yet).
	_ = runRoot("tc", "qdisc", "del", "dev", s.cfg.Interface, "root")
	tree := tcTreeCommands(&s.cfg, s.cfg.Interface)
	for _, args := range tree[1:] {
		cmd := exec.CommandContext(ctx, "tc", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("tc %s: %w", strings.Join(args, " "), err)
		}
	}
	s.qdiscApplied = true
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
	for _, c := range s.spoofs {
		s.killSpoof(c)
	}
	s.spoofs = nil
	if s.cfg.Gateway != "" {
		// Gratuitous ARP so neighbors re-learn the real router MAC quickly.
		if _, err := exec.LookPath("arping"); err == nil {
			_ = runRoot("arping", "-q", "-c", "3", "-U", "-I", s.cfg.Interface, s.cfg.Gateway)
		}
	}
}

func (s *Session) stopCapture() {
	if s.capture == nil {
		return
	}
	_ = s.capture.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.captureWait:
		s.capture = nil
	case <-time.After(3 * time.Second):
		_ = s.capture.Process.Kill()
		<-s.captureWait
		s.capture = nil
	}
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
