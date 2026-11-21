// GNULTE — network testing toolkit (Go).
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL v3.

package engine

import (
	"reflect"
	"strings"
	"testing"
)

// The parsing decisions behind --cleanup are pure: these tests never run tc,
// iptables or any other external command, and never need root.
func TestHasNetemQdisc(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"netem leaf", "qdisc netem 10: dev eth0 parent 1:10 limit 1000\n", true},
		{"netem among other qdiscs", "qdisc htb 1: dev eth0 root refcnt 2\nqdisc netem 10: dev eth0 parent 1:10\n", true},
		{"noqueue only", "qdisc noqueue 0: dev eth0 root refcnt 2\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasNetemQdisc(c.out); got != c.want {
				t.Errorf("hasNetemQdisc(%q) = %v, want %v", c.out, got, c.want)
			}
		})
	}
}

func TestCleanupRuleNumbers(t *testing.T) {
	out := `Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
2    DROP       all  --  192.168.1.50         0.0.0.0/0            /* GNULTE */
3    DROP       all  --  192.168.1.51         0.0.0.0/0            /* GNULTE */
4    DROP       all  --  10.0.0.9             0.0.0.0/0            /* some-admin-rule */
`
	want := []int{2, 3}
	if got := cleanupRuleNumbers(out); !reflect.DeepEqual(got, want) {
		t.Errorf("cleanupRuleNumbers = %v, want %v", got, want)
	}
	if got := cleanupRuleNumbers("Chain FORWARD (policy ACCEPT)\nnum target source destination\n"); len(got) != 0 {
		t.Errorf("header/legend must never be parsed as rules, got %v", got)
	}
	if got := cleanupRuleNumbers("garbage GNULTE line\n"); len(got) != 0 {
		t.Errorf("a line without a rule number must be ignored, got %v", got)
	}
}

func TestBlockRulesCarryCleanupMarker(t *testing.T) {
	c := testCfg()
	for _, r := range blockRules(&c) {
		joined := strings.Join(r, " ")
		if !strings.Contains(joined, "-m comment --comment GNULTE") {
			t.Errorf("block rule is not discoverable by cleanup: %q", joined)
		}
	}
}
