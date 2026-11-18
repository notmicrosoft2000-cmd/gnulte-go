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

// Package report works with the report files the GNULTE tools leave behind. It
// finds reports by their established filenames, merges device snapshots,
// archives reports into dated folders and renders an HTML index. It is pure:
// no sockets, no privileges, no terminal, no clock except an optional file
// modification time fallback during archiving.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gnulte-go/internal/snapshot"
)

// filenamePattern matches the auto-named reports: a tool prefix, a
// YYYYMMDD-HHMMSS stamp, an optional host/target count, and an extension.
// Custom names from --html/-o are not matched; those stay reachable by the
// explicit paths the merge, compare and archive subcommands take.
var filenamePattern = regexp.MustCompile(`^(gnulte-[a-z0-9]+(?:-[a-z0-9]+)*-report)-(\d{8}-\d{6})(?:-(\d+))?\.(html|json)$`)

// Entry is one discovered report file.
type Entry struct {
	Path  string // path as discovered (may be relative)
	Tool  string // e.g. "gnulte-go-scan", "gnulte-scan", "gnulte-watch"
	Stamp string // "YYYYMMDD-HHMMSS", or "" when the filename has no stamp
	Count int    // host/target count from the filename, or 0
	Kind  string // "html" or "json"
}

// parseName returns the parts of an auto-named report, or ok=false.
func parseName(base string) (tool, stamp string, count int, kind string, ok bool) {
	m := filenamePattern.FindStringSubmatch(base)
	if m == nil {
		return "", "", 0, "", false
	}
	tool = strings.TrimSuffix(m[1], "-report")
	stamp = m[2]
	if m[3] != "" {
		count, _ = strconv.Atoi(m[3])
	}
	return tool, stamp, count, m[4], true
}

// Discover walks dirs and returns every auto-named report it finds, newest
// stamp first. A directory that does not exist is skipped, so callers can pass
// the report hub before it has ever been created.
func Discover(dirs ...string) ([]Entry, error) {
	var out []Entry
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("stat %s: %w", dir, err)
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			tool, stamp, count, kind, ok := parseName(d.Name())
			if !ok {
				return nil
			}
			out = append(out, Entry{Path: path, Tool: tool, Stamp: stamp, Count: count, Kind: kind})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", dir, err)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Stamp != out[j].Stamp {
			return out[i].Stamp > out[j].Stamp // fixed width: lexical is chronological
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// Merge loads each snapshot path and folds them into one device list, keyed by
// IP. Later files win for every field they set; earlier files fill the blanks
// they leave. Banner lists are combined in order without duplicates. The
// result is sorted by IP to match snapshot.Compare.
func Merge(paths []string) ([]snapshot.Device, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("merge needs at least one snapshot file")
	}
	order := []string{}
	byIP := map[string]snapshot.Device{}
	for _, path := range paths {
		devices, err := snapshot.Load(path)
		if err != nil {
			return nil, err
		}
		for _, dev := range devices {
			if dev.IP == "" {
				continue
			}
			old, seen := byIP[dev.IP]
			if !seen {
				order = append(order, dev.IP)
				byIP[dev.IP] = dev
				continue
			}
			byIP[dev.IP] = mergeDevice(old, dev)
		}
	}
	out := make([]snapshot.Device, 0, len(order))
	for _, ip := range order {
		out = append(out, byIP[ip])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func mergeDevice(old, next snapshot.Device) snapshot.Device {
	pick := func(a, b string) string {
		if strings.TrimSpace(b) != "" {
			return b
		}
		return a
	}
	old.IP = pick(old.IP, next.IP)
	old.MAC = pick(old.MAC, next.MAC)
	old.Vendor = pick(old.Vendor, next.Vendor)
	old.Hostname = pick(old.Hostname, next.Hostname)
	old.Type = pick(old.Type, next.Type)
	old.OS = pick(old.OS, next.OS)
	old.Ports = pick(old.Ports, next.Ports)
	old.Note = pick(old.Note, next.Note)
	seen := make(map[string]bool, len(old.Banners)+len(next.Banners))
	for _, b := range old.Banners {
		seen[b] = true
	}
	for _, b := range next.Banners {
		if !seen[b] {
			seen[b] = true
			old.Banners = append(old.Banners, b)
		}
	}
	return old
}

// WriteJSON emits devices in the same bare-array format as the -j exports, so
// the result of a merge can be fed straight back into snapshot.Load and
// gnulte --compare.
func WriteJSON(w io.Writer, devices []snapshot.Device) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(devices)
}

// Archive copies files into root/<YYYY>/<MM>/, taking the date from the
// filename stamp when present or the file's modification time otherwise. It
// returns the new paths in input order. An existing destination is never
// overwritten: a -2, -3, ... suffix is added instead.
func Archive(root string, files ...string) ([]string, error) {
	if root == "" {
		return nil, fmt.Errorf("archive needs a destination directory")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, src := range files {
		stamp := ""
		if _, s, _, _, ok := parseName(filepath.Base(src)); ok {
			stamp = s
		}
		date := dateOf(stamp)
		if date == "" {
			info, err := os.Stat(src)
			if err != nil {
				return nil, err
			}
			date = info.ModTime().Format("2006/01")
		}
		dir := filepath.Join(root, date)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		dst, err := copyUnique(src, filepath.Join(dir, filepath.Base(src)))
		if err != nil {
			return nil, err
		}
		out = append(out, dst)
	}
	return out, nil
}

// dateOf turns a YYYYMMDD-HHMMSS stamp into a YYYY/MM folder component.
func dateOf(stamp string) string {
	if len(stamp) < 6 {
		return ""
	}
	year, month := stamp[:4], stamp[4:6]
	if _, err := strconv.Atoi(year); err != nil {
		return ""
	}
	if m, err := strconv.Atoi(month); err != nil || m < 1 || m > 12 {
		return ""
	}
	return year + "/" + month
}

func copyUnique(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	ext := filepath.Ext(dst)
	stem := strings.TrimSuffix(dst, ext)
	for n := 1; ; n++ {
		candidate := dst
		if n > 1 {
			candidate = fmt.Sprintf("%s-%d%s", stem, n, ext)
		}
		out, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return candidate, nil
	}
}

// Index renders a self-contained HTML page listing entries grouped by tool,
// newest first. Every field is escaped; links use the path as discovered.
func Index(entries []Entry) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	b.WriteString("<title>GNULTE report index</title>")
	b.WriteString("<style>body{font-family:ui-monospace,Menlo,monospace;margin:2rem;color:#222}")
	b.WriteString("h2{margin-top:1.6rem}table{border-collapse:collapse;width:100%;margin-top:.5rem}")
	b.WriteString("th,td{border:1px solid #ccc;padding:.35rem .55rem;text-align:left;font-size:.9em}")
	b.WriteString("th{background:#f4f4f4}a{color:#0a5cba}</style></head><body>")
	fmt.Fprintf(&b, "<h1>GNULTE report index</h1><p>%d report(s)</p>", len(entries))
	if len(entries) == 0 {
		b.WriteString("<p>none</p></body></html>")
		return b.String()
	}

	byTool := map[string][]Entry{}
	var tools []string
	for _, e := range entries {
		if _, seen := byTool[e.Tool]; !seen {
			tools = append(tools, e.Tool)
		}
		byTool[e.Tool] = append(byTool[e.Tool], e)
	}
	sort.Strings(tools)
	for _, tool := range tools {
		fmt.Fprintf(&b, "<h2>%s (%d)</h2>", html.EscapeString(tool), len(byTool[tool]))
		b.WriteString("<table><thead><tr><th>WHEN</th><th>HOSTS</th><th>TYPE</th><th>FILE</th></tr></thead><tbody>")
		for _, e := range byTool[tool] {
			b.WriteString("<tr>")
			fmt.Fprintf(&b, "<td>%s</td>", html.EscapeString(prettyStamp(e.Stamp)))
			if e.Count > 0 {
				fmt.Fprintf(&b, "<td>%d</td>", e.Count)
			} else {
				b.WriteString("<td>-</td>")
			}
			fmt.Fprintf(&b, "<td>%s</td>", html.EscapeString(e.Kind))
			link := filepath.ToSlash(e.Path)
			fmt.Fprintf(&b, "<td><a href=\"%s\">%s</a></td></tr>", html.EscapeString(link), html.EscapeString(link))
		}
		b.WriteString("</tbody></table>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

func prettyStamp(stamp string) string {
	if len(stamp) != 15 {
		return stamp
	}
	t, err := time.Parse("20060102-150405", stamp)
	if err != nil {
		return stamp
	}
	return t.Format("2006-01-02 15:04:05")
}
