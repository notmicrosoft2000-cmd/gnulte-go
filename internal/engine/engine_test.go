package engine

import (
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

func TestCaptureArgs(t *testing.T) {
	c := testCfg()
	c.CaptureFile = "out.pcap"
	a := captureArgs(&c, "eth0")
	got := strings.Join(a, " ")
	want := "-i eth0 host 192.168.1.50 host 192.168.1.51 -w out.pcap"
	if got != want {
		t.Errorf("capture args = %q, want %q", got, want)
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
