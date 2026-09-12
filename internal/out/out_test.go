package out

import (
	"testing"

	"gnulte-go/internal/discover"
)

func TestIPLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"192.168.1.2", "192.168.1.10", true},
		{"10.0.0.200", "10.0.1.1", true},
		{"192.168.1.10", "192.168.1.2", false},
		{"1.2.3.4", "1.2.3.4", false},
	}
	for _, c := range cases {
		if got := ipLess(c.a, c.b); got != c.want {
			t.Errorf("ipLess(%s,%s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestAtoi(t *testing.T) {
	if atoi("42") != 42 {
		t.Error("atoi(42) failed")
	}
	if atoi("12x") != 0 {
		t.Error("atoi should reject non-numeric")
	}
}

func TestSortByIP(t *testing.T) {
	rows := []discover.Row{{IP: "192.168.1.10"}, {IP: "192.168.1.2"}, {IP: "10.1.1.1"}}
	SortByIP(rows)
	want := []string{"10.1.1.1", "192.168.1.2", "192.168.1.10"}
	for i, w := range want {
		if rows[i].IP != w {
			t.Errorf("row[%d] = %s, want %s", i, rows[i].IP, w)
		}
	}
}
