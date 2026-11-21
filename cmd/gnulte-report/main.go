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

// Command gnulte-report works with the reports the GNULTE tools leave behind:
// list and index them, merge device snapshots, diff two snapshots, and archive
// reports into dated folders. It touches only local files, so it needs no root
// and no network.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gnulte-go/internal/report"
	"gnulte-go/internal/reportdir"
	"gnulte-go/internal/snapshot"
	"gnulte-go/internal/update"
)

const version = "17.0"

const usageText = `gnulte-report — work with saved GNULTE reports

Usage:
  gnulte-report list [DIR ...]                 list discovered reports
  gnulte-report index [-o FILE] [DIR ...]      write an HTML index of reports
  gnulte-report merge [-o FILE] FILE ...       merge JSON snapshots into one
  gnulte-report compare [-html FILE] A B       diff two JSON snapshots
  gnulte-report archive [-dest DIR] FILE ...   file reports into dated folders

With no DIR, list and index scan the report hub (~/GNULTE Reports). merge and
compare take the -j / --json exports of gnulte-scan or gnulte-inventory. All
output is written to stdout unless -o / -html is given.`

func main() {
	update.MaybeCheck(version, os.Args[1:])
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gnulte-report:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(errOut, usageText)
		return fmt.Errorf("a subcommand is required")
	}
	switch args[0] {
	case "-version", "--version", "-v", "version":
		fmt.Fprintf(out, "gnulte-report (Go) v%s\n", version)
		return nil
	case "-h", "--help", "help":
		fmt.Fprintln(out, usageText)
		return nil
	case "list":
		return runList(args[1:], out, errOut)
	case "index":
		return runIndex(args[1:], out, errOut)
	case "merge":
		return runMerge(args[1:], out, errOut)
	case "compare":
		return runCompare(args[1:], out, errOut)
	case "archive":
		return runArchive(args[1:], out, errOut)
	default:
		fmt.Fprintln(errOut, usageText)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// parse applies a subcommand's flag set. valueFlags names the flags that take
// an argument, so they can appear after positional files as well as before.
// done is true when -h was requested (usage already printed) or parsing failed.
func parse(fs *flag.FlagSet, args []string, out, errOut io.Writer, valueFlags ...string) (bool, error) {
	fs.Usage = func() {}
	args = intersperse(args, valueFlags)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(out, usageText)
			return true, nil
		}
		return true, err
	}
	return false, nil
}

// intersperse moves flags ahead of positional arguments so a value flag such
// as -o works after the filenames too. Flag/value pairs stay adjacent.
func intersperse(args, valueFlags []string) []string {
	takes := make(map[string]bool, len(valueFlags))
	for _, f := range valueFlags {
		takes[f] = true
	}
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if j := strings.IndexByte(name, '='); j >= 0 {
				name = name[:j]
			}
			if takes[name] && !strings.ContainsRune(a, '=') && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		rest = append(rest, a)
	}
	return append(flags, rest...)
}

// defaultDirs is the report hub, or the current directory when the hub cannot
// be resolved (non-interactive processes without a home directory).
func defaultDirs() []string {
	if hub, ok := reportdir.Hub(); ok {
		return []string{hub}
	}
	return []string{"."}
}

func runList(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(errOut)
	if done, err := parse(fs, args, out, errOut); done {
		return err
	}
	dirs := fs.Args()
	if len(dirs) == 0 {
		dirs = defaultDirs()
	}
	entries, err := report.Discover(dirs...)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "no reports found")
		return nil
	}
	fmt.Fprintf(out, "%-18s %-19s %6s %-5s %s\n", "TOOL", "WHEN", "HOSTS", "TYPE", "FILE")
	for _, e := range entries {
		count := "-"
		if e.Count > 0 {
			count = fmt.Sprint(e.Count)
		}
		fmt.Fprintf(out, "%-18s %-19s %6s %-5s %s\n", e.Tool, pretty(e.Stamp), count, e.Kind, e.Path)
	}
	return nil
}

func runIndex(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dst := fs.String("o", "", "write the index to FILE instead of stdout")
	if done, err := parse(fs, args, out, errOut, "o"); done {
		return err
	}
	dirs := fs.Args()
	if len(dirs) == 0 {
		dirs = defaultDirs()
	}
	entries, err := report.Discover(dirs...)
	if err != nil {
		return err
	}
	page := report.Index(entries)
	if *dst != "" {
		if err := os.WriteFile(*dst, []byte(page), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", *dst, err)
		}
		fmt.Fprintf(errOut, "gnulte-report: index written to %s\n", *dst)
		return nil
	}
	fmt.Fprint(out, page)
	return nil
}

func runMerge(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dst := fs.String("o", "", "write the merged snapshot to FILE instead of stdout")
	if done, err := parse(fs, args, out, errOut, "o"); done {
		return err
	}
	paths := fs.Args()
	if len(paths) == 0 {
		return fmt.Errorf("merge needs at least one snapshot file")
	}
	devices, err := report.Merge(paths)
	if err != nil {
		return err
	}
	var sink io.Writer = out
	if *dst != "" {
		f, err := os.Create(*dst)
		if err != nil {
			return fmt.Errorf("write %s: %w", *dst, err)
		}
		defer f.Close()
		sink = f
	}
	if err := report.WriteJSON(sink, devices); err != nil {
		return err
	}
	if *dst != "" {
		fmt.Fprintf(errOut, "gnulte-report: merged %d device(s) into %s\n", len(devices), *dst)
	}
	return nil
}

func runCompare(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(errOut)
	htmlPath := fs.String("html", "", "also write the comparison as an HTML report to FILE")
	if done, err := parse(fs, args, out, errOut, "html"); done {
		return err
	}
	aPath, bPath := "", ""
	rest := fs.Args()
	if len(rest) >= 2 {
		aPath, bPath = rest[0], rest[1]
	} else if len(rest) == 1 {
		if i := strings.IndexByte(rest[0], ','); i >= 0 {
			aPath, bPath = rest[0][:i], rest[0][i+1:]
		}
	}
	if aPath == "" || bPath == "" {
		return fmt.Errorf("compare needs two snapshot files: gnulte-report compare A.json B.json")
	}
	a, err := snapshot.Load(aPath)
	if err != nil {
		return fmt.Errorf("A: %w", err)
	}
	b, err := snapshot.Load(bPath)
	if err != nil {
		return fmt.Errorf("B: %w", err)
	}
	d := snapshot.Compare(a, b)
	snapshot.Render(out, aPath, bPath, d)
	if *htmlPath != "" {
		if err := os.WriteFile(*htmlPath, []byte(snapshot.HTML(aPath, bPath, d)), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", *htmlPath, err)
		}
		fmt.Fprintf(errOut, "gnulte-report: comparison written to %s\n", *htmlPath)
	}
	return nil
}

func runArchive(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("archive", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dest := fs.String("dest", "", "archive root (default: report hub/archive)")
	if done, err := parse(fs, args, out, errOut, "dest"); done {
		return err
	}
	files := fs.Args()
	if len(files) == 0 {
		return fmt.Errorf("archive needs at least one file")
	}
	root := *dest
	if root == "" {
		if hub, ok := reportdir.Hub(); ok {
			root = filepath.Join(hub, "archive")
		} else {
			root = "archive"
		}
	}
	paths, err := report.Archive(root, files...)
	if err != nil {
		return err
	}
	for _, p := range paths {
		fmt.Fprintln(out, p)
	}
	return nil
}

// pretty formats a report stamp for the plain listing; blank stamps stay blank.
func pretty(stamp string) string {
	if stamp == "" {
		return "-"
	}
	if len(stamp) == 15 {
		return stamp[:4] + "-" + stamp[4:6] + "-" + stamp[6:8] + " " + stamp[9:11] + ":" + stamp[11:13] + ":" + stamp[13:15]
	}
	return stamp
}
