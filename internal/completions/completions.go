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

// Package completions generates self-contained shell completion scripts for
// the eight GNULTE binaries. Script is printable: nothing here touches shell
// rc files or the filesystem beyond reading saved profile names.
package completions

import (
	"fmt"
	"sort"
	"strings"

	"gnulte-go/internal/airframes"
	"gnulte-go/internal/profiles"
)

var builtinProfiles = []string{
	"gaming", "streaming", "voip", "web", "extreme", "throttle",
	"satellite", "cellular", "dialup", "congested", "bufferbloat", "nightmare",
}

// commonFlags are accepted across the toolkit (some tools only implement a
// subset, but offering them everywhere keeps the completion table simple).
var commonFlags = []string{
	"--version", "-v", "-h", "--help", "--check-update",
	"--settings", "--docs", "--reset-safety",
	"-q", "--quiet", "--no-report", "-i", "--interface",
}

// tool is one binary's static completion table.
type tool struct {
	name        string
	subcommands []string
	flags       []string
	values      map[string][]string
}

func profileValues() []string {
	values := append([]string(nil), builtinProfiles...)
	saved, err := profiles.List()
	if err == nil {
		for _, name := range saved {
			found := false
			for _, existing := range values {
				if existing == name {
					found = true
					break
				}
			}
			if !found {
				values = append(values, name)
			}
		}
	}
	return values
}

func reasonValues() []string {
	var values []string
	for _, reason := range airframes.ReasonPresets() {
		values = append(values, reason.Name)
	}
	return values
}

func tools() []tool {
	profiles := profileValues()
	reasons := reasonValues()

	return []tool{
		{
			name: "gnulte",
			flags: []string{
				"-t", "--target", "-m", "--mac", "-r", "--range", "-w", "--whitelist",
				"--device-type", "--vendor", "-l", "--latency", "-j", "--jitter",
				"-p", "--loss", "-d", "--duplicate", "-e", "--reorder", "-b", "--bandwidth",
				"--profile", "--list-profiles", "--scenario", "--per-target", "--random",
				"--export", "--note", "--dupcheck", "--compare", "--compare-html",
				"--report", "--duration", "-c", "--capture", "-S", "--stealth",
				"--block", "--sound", "--no-sound", "--echo-commands", "--no-echo-commands",
				"--interval", "--force", "--no-banner", "--minimal", "--from-hub",
				"--traffic-window",
			},
			values: map[string][]string{"--profile": profiles},
		},
		{
			name: "gnulte-scan",
			flags: []string{
				"-C", "--cidr", "-t", "--threads", "-d", "--deep", "-T", "--interactive",
				"-j", "--json", "-y", "--yaml", "-c", "--csv", "--sound", "--arp",
				"--no-arp", "--report", "--watch", "--oui-file",
			},
		},
		{
			name: "gnulte-wifi",
			flags: []string{
				"-a", "--ap", "-s", "--station", "--reason", "--streak", "--count",
				"--delay", "--duration", "--jitter-ms", "--once", "--mix", "--mix-reasons",
				"--hop", "--hop-channels", "--channels", "--list-reasons", "--force",
				"--no-banner", "--minimal",
			},
			values: map[string][]string{"--reason": reasons},
		},
		{
			name:        "gnulte-watch",
			subcommands: []string{"top", "trace"},
			flags: []string{
				"-t", "--interval", "--duration", "--history", "--export", "--json",
				"--history-file", "--no-history", "--alert-debounce", "--alarm-rate",
				"--alarm-latency-ms", "--path", "--trace",
				"-n", "--csv", "--flows", "--host", "--iface",
				"-m", "--html",
			},
		},
		{
			name: "gnulte-inventory",
			flags: []string{
				"-s", "--scan", "-t", "--threads", "-n", "--no-hostnames", "-j", "--json",
				"-y", "--yaml", "-c", "--csv", "-o", "--output", "-H", "--html", "--oui-file",
			},
		},
		{
			name:  "gnulte-quicksum",
			flags: []string{"-j", "--json"},
		},
		{
			name:        "gnulte-report",
			subcommands: []string{"list", "index", "merge", "compare", "archive"},
			flags:       []string{"-o", "--html", "--dest"},
		},
		{
			name:        "gnulte-hub",
			subcommands: []string{"doctor"},
			flags:       []string{"--completions"},
			values:      map[string][]string{"--completions": {"bash", "zsh", "fish"}},
		},
	}
}

func allFlags(t tool) []string {
	seen := make(map[string]bool)
	var flags []string
	for _, f := range append(append([]string(nil), commonFlags...), t.flags...) {
		if !seen[f] {
			seen[f] = true
			flags = append(flags, f)
		}
	}
	return flags
}

func sortedFlagKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Script returns a printable completion script for bash, zsh or fish.
func Script(shell string) (string, error) {
	table := tools()
	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "bash":
		return bashScript(table), nil
	case "zsh":
		return zshScript(table), nil
	case "fish":
		return fishScript(table), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (want bash, zsh or fish)", shell)
	}
}

func bashScript(table []tool) string {
	var b strings.Builder
	b.WriteString("# GNULTE command completions for bash. Source this file; it writes nothing.\n\n")
	for _, t := range table {
		fn := "_gnulte_bash_" + strings.ReplaceAll(t.name, "-", "_")
		fmt.Fprintf(&b, "%s() {\n", fn)
		b.WriteString("    local cur prev\n")
		b.WriteString("    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
		b.WriteString("    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n")
		if len(t.values) > 0 {
			b.WriteString("    case \"$prev\" in\n")
			for _, flag := range sortedFlagKeys(t.values) {
				fmt.Fprintf(&b, "        %s) COMPREPLY=( $(compgen -W %q -- \"$cur\") ); return ;;\n",
					flag, strings.Join(t.values[flag], " "))
			}
			b.WriteString("    esac\n")
		}
		fmt.Fprintf(&b, "    local flags=%q\n", strings.Join(allFlags(t), " "))
		fmt.Fprintf(&b, "    local subs=%q\n", strings.Join(t.subcommands, " "))
		b.WriteString("    case \"$cur\" in\n")
		b.WriteString("        -*) COMPREPLY=( $(compgen -W \"$flags\" -- \"$cur\") ) ;;\n")
		b.WriteString("        *) COMPREPLY=( $(compgen -W \"$subs\" -- \"$cur\") ) ;;\n")
		b.WriteString("    esac\n}\n")
		fmt.Fprintf(&b, "complete -F %s %s\n\n", fn, t.name)
	}
	return b.String()
}

func zshScript(table []tool) string {
	var b strings.Builder
	names := make([]string, 0, len(table))
	for _, t := range table {
		names = append(names, t.name)
	}
	b.WriteString("#compdef " + strings.Join(names, " ") + "\n")
	b.WriteString("# GNULTE command completions for zsh. Source this file; it writes nothing.\n\n")
	b.WriteString("_gnulte_zsh() {\n")
	b.WriteString("    local -a candidates\n")
	b.WriteString("    local cmd=\"${words[1]}\"\n")
	b.WriteString("    local prev=\"${words[CURRENT-1]}\"\n")
	b.WriteString("    case \"${cmd}:${prev}\" in\n")
	for _, t := range table {
		for _, flag := range sortedFlagKeys(t.values) {
			fmt.Fprintf(&b, "        %q) candidates=(%s); compadd -- \"${candidates[@]}\"; return ;;\n",
				t.name+":"+flag, strings.Join(t.values[flag], " "))
		}
	}
	b.WriteString("    esac\n")
	b.WriteString("    case \"$cmd\" in\n")
	for _, t := range table {
		fmt.Fprintf(&b, "        %q) candidates=(%s %s) ;;\n",
			t.name, strings.Join(allFlags(t), " "), strings.Join(t.subcommands, " "))
	}
	b.WriteString("    esac\n")
	b.WriteString("    compadd -- \"${candidates[@]}\"\n")
	b.WriteString("}\n")
	b.WriteString("_gnulte_zsh \"$@\"\n")
	return b.String()
}

func fishScript(table []tool) string {
	var b strings.Builder
	b.WriteString("# GNULTE command completions for fish. Source this file; it writes nothing.\n\n")
	for _, t := range table {
		fmt.Fprintf(&b, "complete -c %s -f\n", t.name)
		for _, flag := range allFlags(t) {
			name := strings.TrimLeft(flag, "-")
			if strings.HasPrefix(flag, "--") {
				fmt.Fprintf(&b, "complete -c %s -l %s -d 'GNULTE option'\n", t.name, name)
			} else {
				fmt.Fprintf(&b, "complete -c %s -s %s -d 'GNULTE option'\n", t.name, name)
			}
		}
		for _, flag := range sortedFlagKeys(t.values) {
			name := strings.TrimLeft(flag, "-")
			if strings.HasPrefix(flag, "--") {
				fmt.Fprintf(&b, "complete -c %s -l %s -a %q\n", t.name, name, strings.Join(t.values[flag], " "))
			} else {
				fmt.Fprintf(&b, "complete -c %s -s %s -a %q\n", t.name, name, strings.Join(t.values[flag], " "))
			}
		}
		if len(t.subcommands) > 0 {
			fmt.Fprintf(&b, "complete -c %s -n '__fish_use_subcommand' -a %q -d 'subcommand'\n",
				t.name, strings.Join(t.subcommands, " "))
		}
		b.WriteString("\n")
	}
	return b.String()
}
