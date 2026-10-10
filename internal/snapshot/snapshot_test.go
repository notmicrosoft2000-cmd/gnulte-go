package snapshot

import (
	"strings"
	"testing"
)

func TestParseArrayAndWrapper(t *testing.T) {
	arr := []byte(`[{"ip":"10.0.0.1","hostname":"router"},{"ip":"10.0.0.2"}]`)
	ds, err := Parse(arr)
	if err != nil || len(ds) != 2 || ds[0].Hostname != "router" {
		t.Fatalf("array parse: %v %+v", err, ds)
	}
	wrap := []byte(`{"kind":"baseline","hosts":[{"ip":"10.0.0.9"}]}`)
	ds, err = Parse(wrap)
	if err != nil || len(ds) != 1 || ds[0].IP != "10.0.0.9" {
		t.Fatalf("wrapper parse: %v %+v", err, ds)
	}
	if _, err := Parse([]byte(`{"nothing":1}`)); err == nil {
		t.Errorf("object without a device array should fail")
	}
	if _, err := Parse(nil); err == nil {
		t.Errorf("empty input should fail")
	}
}

func TestCompare(t *testing.T) {
	a := []Device{
		{IP: "10.0.0.1", Hostname: "router", Vendor: "ACME", Ports: "22/open/tcp/ssh, 80/open/tcp/http"},
		{IP: "10.0.0.2", Hostname: "gone"},
		{IP: "10.0.0.3", Hostname: "nas", Ports: "22/open/tcp/ssh", OS: "Linux"},
	}
	b := []Device{
		{IP: "10.0.0.1", Hostname: "router", Vendor: "ACME", Ports: "22/open/tcp/ssh, 443/open/tcp/https"},
		{IP: "10.0.0.3", Hostname: "nas", Ports: "22/open/tcp/ssh", OS: "Linux"},
		{IP: "10.0.0.4", Hostname: "new"},
	}
	d := Compare(a, b)
	if len(d.Added) != 1 || d.Added[0].IP != "10.0.0.4" {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].IP != "10.0.0.2" {
		t.Errorf("removed = %+v", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].IP != "10.0.0.1" {
		t.Fatalf("changed = %+v", d.Changed)
	}
	var port FieldChange
	for _, f := range d.Changed[0].Fields {
		if f.Field == "ports" {
			port = f
		}
	}
	if port.Before != "-80" || port.After != "+443" {
		t.Errorf("port change = %q -> %q, want -80 -> +443", port.Before, port.After)
	}
	if got := d.Summary(); got != "1 added, 1 removed, 1 changed" {
		t.Errorf("summary = %q", got)
	}
	if d.Empty() {
		t.Errorf("non-empty diff reported as empty")
	}
	if !Compare(a, a).Empty() {
		t.Errorf("identical snapshots must compare empty")
	}
}

func TestCompareDetectsIdentityChange(t *testing.T) {
	a := []Device{{IP: "10.0.0.5", Type: "Phone", MAC: "aa:bb:cc:dd:ee:01"}}
	b := []Device{{IP: "10.0.0.5", Type: "Router/Gateway", MAC: "aa:bb:cc:dd:ee:01"}}
	d := Compare(a, b)
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %+v", d.Changed)
	}
	fs := d.Changed[0].Fields
	if len(fs) != 1 || fs[0].Field != "type" || fs[0].Before != "Phone" || fs[0].After != "Router/Gateway" {
		t.Errorf("fields = %+v", fs)
	}
}

func TestRenderAndHTML(t *testing.T) {
	a := []Device{{IP: "10.0.0.1", Hostname: "router", Ports: "80/open/tcp/http"}}
	b := []Device{{IP: "10.0.0.1", Hostname: "router", Ports: "443/open/tcp/https"}, {IP: "10.0.0.2", Hostname: "<new>"}}
	d := Compare(a, b)

	var human strings.Builder
	Render(&human, "a.json", "b.json", d)
	h := human.String()
	for _, want := range []string{"A: a.json", "B: b.json", "10.0.0.2", "10.0.0.1", "-80", "+443"} {
		if !strings.Contains(h, want) {
			t.Errorf("human report missing %q:\n%s", want, h)
		}
	}

	page := HTML("a.json", "b.json", d)
	for _, want := range []string{"Added", "Removed", "Changed", "10.0.0.2"} {
		if !strings.Contains(page, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if !strings.Contains(page, "&lt;new&gt;") {
		t.Errorf("HTML did not escape the hostname: %s", page)
	}
}
