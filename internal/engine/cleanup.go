// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// cleanupMarker is the iptables comment attached to every FORWARD DROP rule
// inserted by blockRules. It is the only signature Cleanup looks for, so
// unrelated firewall rules are never touched.
const cleanupMarker = "GNULTE"

const forwardPath = "/proc/sys/net/ipv4/ip_forward"

// hasNetemQdisc reports whether `tc qdisc show dev IFACE` output contains a
// netem qdisc — the footprint GNULTE's shaping tree leaves behind. Pure so it
// can be tested without running tc.
func hasNetemQdisc(out string) bool {
	return strings.Contains(strings.ToLower(out), "netem")
}

// cleanupRuleNumbers extracts the line numbers of FORWARD rules carrying the
// GNULTE marker from `iptables -L FORWARD -n -v --line-numbers` output. Only
// rows whose first field is a positive integer are considered, so the chain
// header and the column legend can never be mistaken for a rule. Pure and
// root-free.
func cleanupRuleNumbers(out string) []int {
	var nums []int
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(f[0])
		if err != nil || n < 1 {
			continue
		}
		if strings.Contains(strings.ToUpper(line), cleanupMarker) {
			nums = append(nums, n)
		}
	}
	return nums
}

// cleanupRun runs one privilege-requiring inspection/teardown command in its
// own process group (like Session.runRoot) and returns its combined output.
// Every call is gated by Cleanup's explicit root check.
func cleanupRun(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Cleanup forcibly tears down leftover GNULTE state: the shaping qdisc,
// marked FORWARD DROPs, the ip_forward toggle and (when a gateway is given)
// the real gateway's ARP announcement. It is best-effort — each step is
// recorded as an action or a problem and the caller decides how to report
// them. No command is run unless the caller is root.
func Cleanup(ctx context.Context, iface, gatewayIP string, setForward bool) (actions []string, problems []string) {
	if err := requireRoot(); err != nil {
		return nil, []string{err.Error()}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Shaping tree: only a netem qdisc is ours to remove.
	qout, err := cleanupRun(ctx, "tc", "qdisc", "show", "dev", iface)
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("tc qdisc show: %v", err))
	case hasNetemQdisc(qout):
		del := "tc qdisc del dev " + iface + " root"
		if _, err := cleanupRun(ctx, "tc", "qdisc", "del", "dev", iface, "root"); err != nil {
			problems = append(problems, del+": "+err.Error())
		} else {
			actions = append(actions, del)
		}
	default:
		actions = append(actions, "no GNULTE qdisc found")
	}

	// 2. Block-mode DROPs. Delete from the highest line number down so an
	// earlier deletion cannot renumber a rule we still have to remove.
	// -v is required: iptables omits rule comments (our GNULTE marker) from
	// a plain listing, so without it no marked rule would ever be found.
	iout, err := cleanupRun(ctx, "iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if err != nil {
		problems = append(problems, fmt.Sprintf("iptables -L FORWARD: %v", err))
	} else if nums := cleanupRuleNumbers(iout); len(nums) > 0 {
		for i := len(nums) - 1; i >= 0; i-- {
			line := strconv.Itoa(nums[i])
			del := "iptables -D FORWARD " + line
			if _, err := cleanupRun(ctx, "iptables", "-D", "FORWARD", line); err != nil {
				problems = append(problems, del+": "+err.Error())
			} else {
				actions = append(actions, del)
			}
		}
	} else {
		actions = append(actions, "no GNULTE FORWARD rules found")
	}

	// 3. Forwarding: restoring it is opt-in (block mode had turned it off).
	b, err := os.ReadFile(forwardPath)
	if err != nil {
		problems = append(problems, fmt.Sprintf("read %s: %v", forwardPath, err))
	} else if strings.TrimSpace(string(b)) == "0" {
		if setForward {
			if err := os.WriteFile(forwardPath, []byte("1\n"), 0o644); err != nil {
				problems = append(problems, fmt.Sprintf("write %s: %v", forwardPath, err))
			} else {
				actions = append(actions, "echo 1 > "+forwardPath)
			}
		} else {
			problems = append(problems, "ip_forward is 0; restore it manually with: echo 1 > "+forwardPath+" (or rerun cleanup with --restore-forward)")
		}
	}

	// 4. Re-announce the gateway's real MAC. Reuses the teardown logic: a
	// minimal Session is enough because announceRealGateway only needs the
	// interface and gateway from cfg.
	if gatewayIP != "" {
		s := &Session{cfg: Config{Interface: iface, Gateway: gatewayIP}}
		if err := s.announceRealGateway(); err != nil {
			problems = append(problems, fmt.Sprintf("gateway %s re-announce: %v", gatewayIP, err))
		} else {
			actions = append(actions, fmt.Sprintf("re-announced real gateway %s on %s", gatewayIP, iface))
		}
	}

	return actions, problems
}
