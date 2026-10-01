package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"gnulte-go/internal/doctor"
	"gnulte-go/internal/ux"
)

const version = "16.9"

func main() {
	var (
		asJSON  = flag.Bool("json", false, "output the report as JSON")
		quiet   = flag.Bool("q", false, "quiet: print only warnings and failures")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.BoolVar(asJSON, "j", false, "output the report as JSON")
	flag.BoolVar(quiet, "quiet", false, "quiet: print only warnings and failures")
	flag.BoolVar(showVer, "v", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("gnulte-doctor (Go) v%s\n", version)
		return
	}

	// Gather once, judge purely: the report is a function of the facts, so the
	// same machine always gets the same verdict.
	checks := doctor.Run(doctor.Gather(context.Background()))
	code := doctor.ExitCode(checks)

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(checks); err != nil {
			fmt.Fprintf(os.Stderr, "gnulte-doctor: %v\n", err)
			os.Exit(2)
		}
	case *quiet:
		printProblems(checks)
	default:
		printReport(checks)
	}
	os.Exit(code)
}

// printReport is the human table: one row per check, the fix underneath anything
// that is not passing.
func printReport(checks []doctor.Check) {
	fmt.Fprintln(ux.Out)
	fmt.Fprintln(ux.Out, "  "+ux.C(ux.Header, "GNULTE DOCTOR")+"   "+ux.C(ux.Cyan, "v"+version)+"   "+ux.C(ux.Dim, "pre-flight health check"))
	fmt.Fprintln(ux.Out)
	for _, c := range checks {
		fmt.Fprintf(ux.Out, "  %s  %-22s %s\n", statusLabel(c.Status), c.Name, c.Detail)
		if c.Hint != "" && c.Status != doctor.Pass {
			fmt.Fprintf(ux.Out, "        %-22s %s\n", "", ux.C(ux.Dim, "fix: "+c.Hint))
		}
	}
	pass, warn, fail := doctor.Counts(checks)
	fmt.Fprintln(ux.Out)
	fmt.Fprintf(ux.Out, "  %d passed, %d warning(s), %d failure(s)\n", pass, warn, fail)
	switch {
	case fail > 0:
		fmt.Fprintln(ux.Out, "  "+ux.C(ux.Red, "NOT READY")+" — fix the failures above.")
	case warn > 0:
		fmt.Fprintln(ux.Out, "  "+ux.C(ux.Yellow, "READY")+" — with warnings.")
	default:
		fmt.Fprintln(ux.Out, "  "+ux.C(ux.Green, "READY")+".")
	}
	fmt.Fprintln(ux.Out)
}

// printProblems is the script/quiet view: nothing when the machine is healthy,
// otherwise the non-passing rows only.
func printProblems(checks []doctor.Check) {
	for _, c := range checks {
		if c.Status == doctor.Pass {
			continue
		}
		fmt.Printf("%s %s: %s\n", c.Status, c.Name, c.Detail)
		if c.Hint != "" {
			fmt.Printf("    fix: %s\n", c.Hint)
		}
	}
}

func statusLabel(s doctor.Status) string {
	switch s {
	case doctor.Pass:
		return ux.C(ux.Green, "PASS")
	case doctor.Warn:
		return ux.C(ux.Yellow, "WARN")
	default:
		return ux.C(ux.Red, "FAIL")
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gnulte-doctor v%s — check whether this machine is ready to run GNULTE.

Usage:
  gnulte-doctor [flags]

Flags:
  -j, --json      print the report as JSON (machine readable)
  -q, --quiet     print only warnings and failures
  -v, --version   print version and exit

The doctor checks privileges, the tc/iptables binaries, ip_forward, the netem
and netfilter kernel modules, the default route and interface, duplicate IPs on
the LAN, and the safety-notice acceptance record. It exits non-zero if any
check fails, so it can gate a script or a CI step.

Install missing pieces with the project's install.sh, or your package manager
(iproute2 for tc, iptables for block mode).
`, version)
}
