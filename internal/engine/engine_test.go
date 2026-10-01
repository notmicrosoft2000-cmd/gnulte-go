package engine

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func testCfg() Config {
	return Config{
		Interface:  "eth0",
		Gateway:    "192.168.1.1",
		Targets:    []string{"192.168.1.50", "192.168.1.51"},
		LatencyMS:  300,
		JitterMS:   100,
		LossPct:    5,
		DupPct:     2,
		ReorderPct: 3,
	}
}

func TestNetemArgs(t *testing.T) {
	c := testCfg()
	a := netemArgs(&c)
	want := "delay 300ms 100ms loss 5% duplicate 2% reorder 3% gap 5"
	if got := strings.Join(a, " "); got != want {
		t.Errorf("netem args = %q, want %q", got, want)
	}
	a = netemArgs(&Config{})
	if got := strings.Join(a, " "); got != "delay 0ms 0ms" {
		t.Errorf("zero netem args = %q", got)
	}
}

func TestNetemZeroPercentOmitted(t *testing.T) {
	c := testCfg()
	c.LossPct = 0
	c.DupPct = 0
	c.ReorderPct = 0
	a := netemArgs(&c)
	if got := strings.Join(a, " "); got != "delay 300ms 100ms" {
		t.Errorf("expected loss/dup/reorder omitted, got %q", got)
	}
}

func TestRate(t *testing.T) {
	c := testCfg()
	if rate(&c) != "1gbit" {
		t.Error("default rate should be 1gbit")
	}
	c.BandwidthKbps = 512
	if rate(&c) != "512kbit" {
		t.Errorf("rate = %s, want 512kbit", rate(&c))
	}
}

func TestTCTreeCommands(t *testing.T) {
	c := testCfg()
	cmds := tcTreeCommands(&c, "eth0")
	var flat []string
	for _, ar := range cmds {
		flat = append(flat, strings.Join(ar, " "))
	}
	joined := strings.Join(flat, "\n")
	for _, want := range []string{
		"qdisc del dev eth0 root",
		"qdisc add dev eth0 root handle 1: htb default 999",
		"class add dev eth0 parent 1: classid 1:999 htb rate 1gbit ceil 1gbit",
		"class add dev eth0 parent 1: classid 1:10 htb rate 1gbit ceil 1gbit",
		"qdisc add dev eth0 parent 1:10 handle 10: netem delay 300ms 100ms loss 5% duplicate 2% reorder 3% gap 5",
		"filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dst 192.168.1.50/32 flowid 1:10",
		"filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip src 192.168.1.50/32 flowid 1:10",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("tc tree missing %q\nfull:\n%s", want, joined)
		}
	}
}

func TestTCChangeCommands(t *testing.T) {
	c := testCfg()
	cmds := tcChangeCommands(&c, "eth0")
	joined := strings.Join([]string{strings.Join(cmds[0], " "), strings.Join(cmds[1], " ")}, "\n")
	for _, want := range []string{
		"class change dev eth0 parent 1: classid 1:10 htb rate 1gbit ceil 1gbit",
		"qdisc change dev eth0 parent 1:10 handle 10: netem",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("change tree missing %q", want)
		}
	}
}

func TestBlockRules(t *testing.T) {
	c := testCfg()
	rules := blockRules(&c)
	joined := strings.Join(func() []string {
		var s []string
		for _, r := range rules {
			s = append(s, strings.Join(r, " "))
		}
		return s
	}(), "\n")
	for _, want := range []string{
		"-d 192.168.1.50 -j DROP",
		"-s 192.168.1.50 -j DROP",
		"-d 192.168.1.51 -j DROP",
		"-s 192.168.1.51 -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("block rules missing %q\n%q", want, joined)
		}
	}
	// Range start is skipped in block mode.
	c2 := testCfg()
	c2.RangeStart = "192.168.1.51"
	rules2 := blockRules(&c2)
	for _, r := range rules2 {
		if strings.Contains(strings.Join(r, " "), "192.168.1.51") {
			t.Errorf("range-start host must not be dropped: %v", r)
		}
	}
}

// ethFrame wraps a network-layer body in an Ethernet header with the ethertype
// in its usual place, and VLAN tags in front when tags are given.
func ethFrame(etherType uint16, body []byte, vlan ...uint16) []byte {
	f := make([]byte, 12) // dst + src MAC
	for _, v := range vlan {
		var tag [4]byte
		binary.BigEndian.PutUint16(tag[0:2], 0x8100)
		binary.BigEndian.PutUint16(tag[2:4], v)
		f = append(f, tag[:]...)
	}
	var et [2]byte
	binary.BigEndian.PutUint16(et[:], etherType)
	f = append(f, et[:]...)
	return append(f, body...)
}

func ipv4Body(src, dst string) []byte {
	b := make([]byte, 20, 28)
	b[0] = 0x45
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	return b
}

func ipv6Body(src, dst string) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	copy(b[8:24], net.ParseIP(src).To16())
	copy(b[24:40], net.ParseIP(dst).To16())
	return b
}

// TestCaptureFilter is the heart of the in-Go --capture: the host filter decides
// which frames land in the file, so a frame to or from a target must be kept and
// an unrelated one dropped. The old tcpdump `host <target>` arguments are
// replaced by this predicate, so it has to be exact.
func TestCaptureFilter(t *testing.T) {
	targets := hostSet([]string{"192.168.1.50", "192.168.1.51", "2001:db8::5"})
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"target is the destination", ethFrame(0x0800, ipv4Body("10.0.0.9", "192.168.1.50")), true},
		{"target is the source", ethFrame(0x0800, ipv4Body("192.168.1.51", "10.0.0.9")), true},
		{"neither end is a target", ethFrame(0x0800, ipv4Body("10.0.0.9", "10.0.0.10")), false},
		{"target as an IPv6 source", ethFrame(0x86dd, ipv6Body("2001:db8::5", "2001:db8::1")), true},
		{"unrelated IPv6", ethFrame(0x86dd, ipv6Body("2001:db8::1", "2001:db8::2")), false},
		{"VLAN-tagged target", ethFrame(0x0800, ipv4Body("192.168.1.50", "10.0.0.9"), 42), true},
		{"ARP is not attributed to a host", ethFrame(0x0806, make([]byte, 28)), false},
		{"a runt frame is not matched", []byte{1, 2, 3}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := frameMatches(c.frame, targets); got != c.want {
				t.Fatalf("frameMatches = %v, want %v", got, c.want)
			}
		})
	}

	// With no target filter, everything is captured — the tcpdump default.
	if !frameMatches(ethFrame(0x0806, make([]byte, 28)), hostSet(nil)) {
		t.Fatal("an empty filter must capture non-IP frames")
	}
}

// TestHostSetNormalizesAddresses: the filter compares raw bytes, so a target
// written in a different-but-equal form (IPv4-mapped IPv6, expansion) must still
// produce the four-byte IPv4 key an Ethernet frame carries.
func TestHostSetNormalizesAddresses(t *testing.T) {
	set := hostSet([]string{"192.168.1.50", "::ffff:192.168.1.51", "not-an-ip"})
	if len(set) != 2 {
		t.Fatalf("set has %d keys, want 2 (the unparseable entry must be dropped): %v", len(set), set)
	}
	if !frameMatches(ethFrame(0x0800, ipv4Body("0.0.0.0", "192.168.1.51")), set) {
		t.Fatal("IPv4-mapped target did not match a plain IPv4 frame")
	}
}

func TestRestoreQdiscArgs(t *testing.T) {
	for _, noop := range []string{
		"qdisc noqueue 0: dev eth0 root refcnt 2",
		"qdisc none 0: dev eth0 root refcnt 2",
		"qdisc nomatch 0: dev eth0 root refcnt 2",
		"",
		"garbage that cannot parse",
	} {
		if args := restoreQdiscArgs("eth0", noop); args != nil {
			t.Errorf("expected no restore for %q, got %v", noop, args)
		}
	}
	args := restoreQdiscArgs("eth0", "qdisc fq_codel 0: dev eth0 root refcnt 2 limit 10240p flows 1024 quantum 1514b")
	if args == nil {
		t.Fatal("expected restore command for fq_codel")
	}
	got := strings.Join(args, " ")
	want := "qdisc add dev eth0 root handle 0: fq_codel limit 10240p flows 1024 quantum 1514b"
	if got != want {
		t.Errorf("restore = %q, want %q", got, want)
	}
}

func TestValidateRejectsBad(t *testing.T) {
	c := Config{Interface: "", Gateway: "1.1.1.1", Targets: []string{"192.168.1.5"}, LossPct: 101}
	if err := c.Validate(); err == nil {
		t.Error("expected validation error for >100% loss")
	}
	c = Config{Interface: "eth0", Gateway: "1.1.1.1", Targets: []string{"nope"}, LossPct: 0}
	if err := c.Validate(); err == nil {
		t.Error("expected validation error for invalid target")
	}
}
