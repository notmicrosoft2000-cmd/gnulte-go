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

// Package snapshot reads device-list JSON exports (gnulte-scan / gnulte-devices
// -j output) and diffs two of them, so an operator can answer "what changed on
// my network since last time?" without replaying a full scan. It is pure: no
// sockets, no clock, no terminal.
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Device is one host in a snapshot, matching the fields the -j exports emit.
type Device struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	Type     string   `json:"type,omitempty"`
	OS       string   `json:"os,omitempty"`
	Ports    string   `json:"ports,omitempty"`
	Banners  []string `json:"banners,omitempty"`
	Note     string   `json:"scan_note,omitempty"`
}

// FieldChange is one attribute that moved between the two snapshots.
type FieldChange struct {
	Field  string
	Before string
	After  string
}

// HostChange collects every field change for one host.
type HostChange struct {
	IP     string
	Host   string
	Fields []FieldChange
}

// Diff is the whole comparison.
type Diff struct {
	Added   []Device
	Removed []Device
	Changed []HostChange
}

// Empty reports whether the two snapshots are identical.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Summary renders the one-line tally.
func (d Diff) Summary() string {
	return fmt.Sprintf("%d added, %d removed, %d changed",
		len(d.Added), len(d.Removed), len(d.Changed))
}

// Load reads a snapshot file.
func Load(path string) ([]Device, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ds, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ds, nil
}

// Parse accepts either a bare array of devices (the -j format) or an object
// carrying "hosts" / "devices".
func Parse(raw []byte) ([]Device, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty snapshot")
	}
	if trimmed[0] == '[' {
		var ds []Device
		if err := json.Unmarshal(trimmed, &ds); err != nil {
			return nil, err
		}
		return ds, nil
	}
	var wrapper struct {
		Hosts   []Device `json:"hosts"`
		Devices []Device `json:"devices"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err != nil {
		return nil, err
	}
	switch {
	case wrapper.Hosts != nil:
		return wrapper.Hosts, nil
	case wrapper.Devices != nil:
		return wrapper.Devices, nil
	}
	return nil, fmt.Errorf("no device array in snapshot")
}

// Compare diffs b against a: hosts only in b are added, only in a removed, and
// hosts in both with a moved attribute are changed.
func Compare(a, b []Device) Diff {
	am := index(a)
	bm := index(b)
	var d Diff
	for _, x := range b {
		if _, ok := am[x.IP]; !ok {
			d.Added = append(d.Added, x)
		}
	}
	for _, x := range a {
		if _, ok := bm[x.IP]; !ok {
			d.Removed = append(d.Removed, x)
		}
	}
	for _, x := range b {
		y, ok := am[x.IP]
		if !ok {
			continue
		}
		if fs := diffDevice(y, x); len(fs) > 0 {
			d.Changed = append(d.Changed, HostChange{IP: x.IP, Host: firstNonEmpty(x.Hostname, y.Hostname), Fields: fs})
		}
	}
	byIP := func(ds []Device) {
		sort.Slice(ds, func(i, j int) bool { return ds[i].IP < ds[j].IP })
	}
	byIP(d.Added)
	byIP(d.Removed)
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].IP < d.Changed[j].IP })
	return d
}

func index(ds []Device) map[string]Device {
	m := make(map[string]Device, len(ds))
	for _, d := range ds {
		m[d.IP] = d
	}
	return m
}

// diffDevice compares the attributes worth alerting on, in a stable order.
func diffDevice(a, b Device) []FieldChange {
	var out []FieldChange
	add := func(field, before, after string) {
		if before != after {
			out = append(out, FieldChange{Field: field, Before: before, After: after})
		}
	}
	add("vendor", a.Vendor, b.Vendor)
	add("hostname", a.Hostname, b.Hostname)
	add("type", a.Type, b.Type)
	add("os", a.OS, b.OS)
	add("mac", a.MAC, b.MAC)

	if a.Ports != b.Ports {
		appeared, closed := portDelta(parsePorts(a.Ports), parsePorts(b.Ports))
		before, after := portDeltaText(closed, appeared, true), portDeltaText(closed, appeared, false)
		if before == "" && after == "" {
			before, after = a.Ports, b.Ports
		}
		out = append(out, FieldChange{Field: "ports", Before: before, After: after})
	}
	if strings.Join(a.Banners, "\n") != strings.Join(b.Banners, "\n") {
		out = append(out, FieldChange{Field: "banners", Before: strings.Join(a.Banners, "; "), After: strings.Join(b.Banners, "; ")})
	}
	return out
}

// parsePorts pulls the leading port number out of each comma-separated entry of
// a formatted port string ("22/open/tcp/ssh, 80/open/tcp/http").
func parsePorts(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		i := 0
		for i < len(part) && part[i] >= '0' && part[i] <= '9' {
			i++
		}
		if i == 0 {
			continue
		}
		if n, err := strconv.Atoi(part[:i]); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func portDelta(prev, cur []int) (appeared, closed []int) {
	p, c := map[int]bool{}, map[int]bool{}
	for _, n := range prev {
		p[n] = true
	}
	for _, n := range cur {
		c[n] = true
	}
	for n := range c {
		if !p[n] {
			appeared = append(appeared, n)
		}
	}
	for n := range p {
		if !c[n] {
			closed = append(closed, n)
		}
	}
	sort.Ints(appeared)
	sort.Ints(closed)
	return appeared, closed
}

// portDeltaText renders one side of a port move: the closed set reads as the
// list of "gone" ports, the appeared side as the "new" ones.
func portDeltaText(closed, appeared []int, before bool) string {
	mark, list := "+", appeared
	if before {
		mark, list = "-", closed
	}
	if len(list) == 0 {
		return ""
	}
	parts := make([]string, len(list))
	for i, n := range list {
		parts[i] = mark + strconv.Itoa(n)
	}
	return strings.Join(parts, " ")
}

// Label is a device's best human name.
func Label(d Device) string {
	return firstNonEmpty(d.Hostname, d.Vendor, d.Type, d.MAC)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// Render writes the human "what changed" report.
func Render(w io.Writer, aPath, bPath string, d Diff) {
	fmt.Fprintf(w, "GNULTE compare\n  A: %s\n  B: %s\n\n", aPath, bPath)
	if d.Empty() {
		fmt.Fprint(w, "no change\n")
		return
	}
	for _, x := range d.Added {
		fmt.Fprintf(w, "  + %-15s %s\n", x.IP, Label(x))
	}
	for _, x := range d.Removed {
		fmt.Fprintf(w, "  - %-15s %s\n", x.IP, Label(x))
	}
	for _, c := range d.Changed {
		fmt.Fprintf(w, "  ~ %-15s %s\n", c.IP, c.Host)
		for _, f := range c.Fields {
			fmt.Fprintf(w, "      %-9s %s -> %s\n", f.Field, orDash(f.Before), orDash(f.After))
		}
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// HTML renders the comparison as a self-contained report.
func HTML(aPath, bPath string, d Diff) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	b.WriteString("<title>GNULTE compare</title>")
	b.WriteString("<style>body{font-family:ui-monospace,Menlo,monospace;margin:2rem;color:#222}")
	b.WriteString("h2{margin-top:1.6rem}table{border-collapse:collapse;width:100%;margin-top:.6rem}")
	b.WriteString("th,td{border:1px solid #ccc;padding:.35rem .55rem;text-align:left;font-size:.9em}")
	b.WriteString("th{background:#f4f4f4}.add{color:#1a7f37}.del{color:#b42318}.chg{color:#9a6700}")
	b.WriteString("code{background:#f6f8fa;padding:.05rem .3rem;border-radius:3px}</style></head><body>")
	b.WriteString("<h1>GNULTE compare</h1>")
	fmt.Fprintf(&b, "<p><b>A</b> %s &nbsp;→&nbsp; <b>B</b> %s &nbsp;·&nbsp; %s</p>",
		html.EscapeString(aPath), html.EscapeString(bPath), html.EscapeString(d.Summary()))

	writeTable := func(title, class string, ds []Device) {
		fmt.Fprintf(&b, "<h2 class=\"%s\">%s (%d)</h2>", class, title, len(ds))
		if len(ds) == 0 {
			b.WriteString("<p>none</p>")
			return
		}
		b.WriteString("<table><thead><tr><th>IP</th><th>NAME</th><th>MAC</th><th>VENDOR</th><th>TYPE</th><th>PORTS</th></tr></thead><tbody>")
		for _, x := range ds {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				html.EscapeString(x.IP), html.EscapeString(Label(x)), html.EscapeString(x.MAC),
				html.EscapeString(x.Vendor), html.EscapeString(x.Type), html.EscapeString(orDash(x.Ports)))
		}
		b.WriteString("</tbody></table>")
	}
	writeTable("Added", "add", d.Added)
	writeTable("Removed", "del", d.Removed)

	b.WriteString("<h2 class=\"chg\">Changed</h2>")
	if len(d.Changed) == 0 {
		b.WriteString("<p>none</p>")
	} else {
		b.WriteString("<table><thead><tr><th>IP</th><th>NAME</th><th>FIELD</th><th>BEFORE</th><th>AFTER</th></tr></thead><tbody>")
		for _, c := range d.Changed {
			for _, f := range c.Fields {
				fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>",
					html.EscapeString(c.IP), html.EscapeString(c.Host), html.EscapeString(f.Field),
					html.EscapeString(orDash(f.Before)), html.EscapeString(orDash(f.After)))
			}
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("</body></html>")
	return b.String()
}
