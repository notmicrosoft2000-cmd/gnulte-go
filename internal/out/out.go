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

// Package out renders scan results as a human table, JSON, YAML, or CSV.
package out

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"gnulte-go/internal/discover"
)

// Table writes an aligned, colour-free table (terminals stay parseable).
func Table(w io.Writer, rows []discover.Row) {
	// Build header list. ORDER matches scan: MAC, VENDOR, HOSTNAME, TYPE.
	nameByIndex := []string{"MAC", "VENDOR", "HOSTNAME", "TYPE"}
	visible := []bool{true} // IP always visible
	for _, idx := range []int{0, 1, 2, 3} {
		on := false
		for _, r := range rows {
			switch idx {
			case 0:
				on = on || r.MAC != ""
			case 1:
				on = on || r.Vendor != ""
			case 2:
				on = on || r.Hostname != ""
			case 3:
				on = on || r.Type != ""
			}
			if on {
				break
			}
		}
		visible = append(visible, on)
	}
	headers := []string{"IP"}
	for i, name := range nameByIndex {
		if visible[i+1] {
			headers = append(headers, name)
		}
	}
	if len(rows) > 0 && rows[0].Ports != "" {
		headers = append(headers, "PORTS")
	}
	if len(rows) > 0 && rows[0].OS != "" {
		headers = append(headers, "OS")
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	values := make([][]string, 0, len(rows))
	for _, r := range rows {
		v := []string{orDash(r.IP)}
		for j, on := range visible[1:] {
			if on {
				var s string
				switch j {
				case 0:
					s = r.MAC
				case 1:
					s = r.Vendor
				case 2:
					s = r.Hostname
				case 3:
					s = r.Type
				}
				v = append(v, orDash(s))
			}
		}
		if len(headers) > len(v) {
			v = append(v, orDash(r.Ports))
		}
		if len(headers) > len(v) {
			v = append(v, orDash(r.OS))
		}
		for i, s := range v {
			if len(s) > widths[i] {
				widths[i] = len(s)
			}
		}
		values = append(values, v)
	}
	sep := ""
	for _, wd := range widths {
		sep += strings.Repeat("─", wd+2)
	}
	fmt.Fprintln(w, sep)
	cells := make([]string, len(headers))
	for i, h := range headers {
		cells[i] = pad(h, widths[i])
	}
	fmt.Fprintln(w, " "+strings.Join(cells, "  "))
	fmt.Fprintln(w, sep)
	for _, v := range values {
		for i, s := range v {
			cells[i] = pad(s, widths[i])
		}
		fmt.Fprintln(w, " "+strings.Join(cells, "  "))
	}
	fmt.Fprintln(w, sep)
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// JSON writes an array of host objects.
func JSON(w io.Writer, rows []discover.Row) error {
	type host struct {
		IP       string   `json:"ip"`
		MAC      string   `json:"mac,omitempty"`
		Vendor   string   `json:"vendor,omitempty"`
		Hostname string   `json:"hostname,omitempty"`
		Type     string   `json:"type,omitempty"`
		Ports    string   `json:"ports,omitempty"`
		OS       string   `json:"os,omitempty"`
		Banners  []string `json:"banners,omitempty"`
		ScanNote string   `json:"scan_note,omitempty"`
	}
	list := make([]host, 0, len(rows))
	for _, r := range rows {
		list = append(list, host{r.IP, r.MAC, r.Vendor, r.Hostname, r.Type, r.Ports, r.OS, r.Banners, r.ScanNote})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(list)
}

// YAML writes a minimal, dependency-free YAML list.
func YAML(w io.Writer, rows []discover.Row) error {
	fmt.Fprintln(w, "hosts:")
	for _, r := range rows {
		fmt.Fprintf(w, "  - ip: %q\n", r.IP)
		if r.MAC != "" {
			fmt.Fprintf(w, "    mac: %q\n", r.MAC)
		}
		if r.Vendor != "" {
			fmt.Fprintf(w, "    vendor: %q\n", r.Vendor)
		}
		if r.Hostname != "" {
			fmt.Fprintf(w, "    hostname: %q\n", r.Hostname)
		}
		if r.Type != "" {
			fmt.Fprintf(w, "    type: %q\n", r.Type)
		}
		if r.Ports != "" {
			fmt.Fprintf(w, "    ports: %q\n", r.Ports)
		}
		if r.OS != "" {
			fmt.Fprintf(w, "    os: %q\n", r.OS)
		}
		for _, b := range r.Banners {
			fmt.Fprintf(w, "    - banner: %q\n", b)
		}
		if r.ScanNote != "" {
			fmt.Fprintf(w, "    scan_note: %q\n", r.ScanNote)
		}
	}
	return nil
}

// CSV writes a header row followed by one row per host.
func CSV(w io.Writer, rows []discover.Row) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"ip", "mac", "vendor", "hostname", "type", "ports", "os", "banners", "scan_note"}); err != nil {
		return err
	}
	for _, r := range rows {
		if err := cw.Write([]string{r.IP, r.MAC, r.Vendor, r.Hostname, r.Type, r.Ports, r.OS, strings.Join(r.Banners, " | "), r.ScanNote}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// SortByIP orders rows numerically by IPv4.
func SortByIP(rows []discover.Row) {
	sort.SliceStable(rows, func(i, j int) bool {
		return ipLess(rows[i].IP, rows[j].IP)
	})
}

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return atoi(pa[i]) < atoi(pb[i])
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
