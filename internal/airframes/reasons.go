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

package airframes

import (
	"fmt"
	"strconv"
	"strings"
)

// Reason is a named 802.11 deauthentication reason code.
type Reason struct {
	Name string
	Code uint16
	Desc string
}

// ReasonPresets returns the named reasons accepted by --reason, in code order.
// The names are short enough to type and map to ordinary disconnect reasons,
// so a named run reads the same to a station as a numeric one.
func ReasonPresets() []Reason {
	return []Reason{
		{Name: "unspecified", Code: 1, Desc: "reason unspecified"},
		{Name: "auth-invalid", Code: 2, Desc: "previous authentication no longer valid"},
		{Name: "left-ess", Code: 3, Desc: "station left the ESS"},
		{Name: "inactivity", Code: 4, Desc: "disassociated due to inactivity"},
		{Name: "ap-overload", Code: 5, Desc: "AP cannot handle more stations"},
		{Name: "class2", Code: 6, Desc: "class 2 frame from an unauthenticated station"},
		{Name: "leaving", Code: 7, Desc: "station leaving the BSS (default)"},
		{Name: "auth-unsupported", Code: 8, Desc: "authentication algorithm not supported"},
		{Name: "assoc-rejected", Code: 9, Desc: "association rejected"},
		{Name: "handshake", Code: 23, Desc: "four-way handshake timeout"},
	}
}

// reasonAliases are short spellings for the reasons people reach for most. The
// default stays 7, whichever spelling is used.
var reasonAliases = map[string]string{
	"default":  "leaving",
	"left":     "leaving",
	"inactive": "inactivity",
	"fourway":  "handshake",
	"4way":     "handshake",
}

// ParseReason accepts a numeric code (0-65535) or a preset name, case
// insensitively. It returns the code, the canonical name (empty for an
// unnamed numeric code), and an error listing valid names when input is bad.
func ParseReason(s string) (uint16, string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return 0, "", fmt.Errorf("empty reason")
	}
	presets := ReasonPresets()
	// Resolve aliases first: "4way" starts with a digit but is a name, not a code.
	if alias, ok := reasonAliases[v]; ok {
		v = alias
	}
	if v[0] >= '0' && v[0] <= '9' {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return 0, "", fmt.Errorf("reason code must be 0-65535 (got %q)", s)
		}
		return uint16(n), ReasonName(uint16(n)), nil
	}
	for _, p := range presets {
		if p.Name == v {
			return p.Code, p.Name, nil
		}
	}
	names := make([]string, 0, len(presets))
	for _, p := range presets {
		names = append(names, p.Name)
	}
	return 0, "", fmt.Errorf("unknown reason %q; use a code 0-65535 or one of: %s", s, strings.Join(names, ", "))
}

// ReasonName returns the canonical name for a code, or "" when the code has no
// preset. The first preset wins if several share a code.
func ReasonName(code uint16) string {
	for _, p := range ReasonPresets() {
		if p.Code == code {
			return p.Name
		}
	}
	return ""
}

// FormatReason renders a code with its name when known: "7 (leaving)", or just
// "42" for an unnamed numeric code.
func FormatReason(code uint16) string {
	if name := ReasonName(code); name != "" {
		return fmt.Sprintf("%d (%s)", code, name)
	}
	return strconv.FormatUint(uint64(code), 10)
}
