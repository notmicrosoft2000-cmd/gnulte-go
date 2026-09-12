// GNULTE-GO — network testing toolkit.
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

// Package safety implements the GNULTE first-run acceptance gate.
//
// Unlike the Bash version this is a redesign: the record is a strict JSON
// data file (never executed) written atomically with 0600 permissions under
// $XDG_CONFIG_HOME|~/.config/gnulte-go/acceptance.json.
//
// Design rules:
//   - No flag, environment variable, or hidden state bypasses the gate.
//   - Non-interactive stdin means we refuse and exit 1.
//   - The record only says the documents were shown and acknowledged, and it
//     cannot make unauthorized testing lawful.
package safety

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PolicyVersion is bumped whenever the notices change; an older record then
// triggers onboarding again. Start at 1 (fresh design, fresh name).
const PolicyVersion = 1

const policyName = "GNULTE-GO"

var docs = []struct {
	Name string
	Text string
}{
	{"LICENSE",
		"GNU GPL version 3 or later. See the LICENSE file in the GNULTE\n" +
			"repository for the full official text. It covers redistribution and\n" +
			"modification only and grants no permission to test any network."},
	{"SAFETY",
		"GNULTE-GO can perform ARP-based man-in-the-middle operation, traffic\n" +
			"manipulation, impairment, packet capture, and LAN discovery/active\n" +
			"reconnaissance. Use these only on networks/devices you own or are\n" +
			"explicitly authorized to test. Capture and impairment can affect\n" +
			"other people."},
	{"DISCLAIMER",
		"Provided AS IS, without warranty, to the maximum extent permitted by\n" +
			"law. You are solely responsible for authorization and compliance.\n" +
			"This does not modify or supersede the GPL."},
	{"AUTHORIZED-USE",
		"Before you begin, record who authorized the test, which systems/IPs\n" +
			"are in scope or excluded, which techniques are allowed, whether\n" +
			"capture/disruption is permitted, the testing window, and an\n" +
			"emergency contact."},
	{"NETWORK-TESTING",
		"Controlled testing chain: discovery finds targets, the test engine\n" +
			"reproduces latency/jitter/loss/duplication/reorder/bandwidth\n" +
			"conditions or a full block against authorized targets so\n" +
			"applications can be observed under bad networks."},
}

// Notice is the text shown before any interactive prompt.
const notice = `IMPORTANT GNULTE-GO SAFETY NOTICE

GNULTE-GO MAY:
* Perform ARP-based man-in-the-middle operations.
* Manipulate, degrade, throttle, or fully block network traffic.
* Capture network traffic.
* Discover devices and run active reconnaissance on a LAN.

ONLY USE THESE FEATURES ON NETWORKS AND SYSTEMS THAT YOU OWN OR
ARE EXPLICITLY AUTHORIZED TO TEST.

DO NOT USE GNULTE-GO TO INTERCEPT, DISRUPT, DEGRADE, CAPTURE, OR
MODIFY OTHER PEOPLE'S TRAFFIC WITHOUT AUTHORIZATION.

THE SOFTWARE IS PROVIDED WITHOUT WARRANTY TO THE MAXIMUM EXTENT
PERMITTED BY APPLICABLE LAW.

Required documents:
`

// Acceptance is the data written to disk. It is DATA ONLY — the program
// parses it with encoding/json; it is never eval'd or sourced.
type Acceptance struct {
	PolicyName      string          `json:"policy_name"`
	PolicyVersion   int             `json:"policy_version"`
	AcceptedAt      time.Time       `json:"accepted_at"`
	DocumentsShown  []string        `json:"documents_shown"`
	Acknowledgments map[string]bool `json:"acknowledgments"`
}

// RecordPath returns the acceptance file location for the current user.
func RecordPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			base = "/tmp"
		} else {
			base = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(base, "gnulte-go", "acceptance.json")
}

// DocText returns the embedded text for a document name, or "".
func DocText(name string) string {
	for _, d := range docs {
		if d.Name == name {
			return d.Text
		}
	}
	return ""
}

// AllDocNames lists the documents in review order.
func AllDocNames() []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Name)
	}
	return out
}

// Valid reports whether an existing record is current and complete.
func Valid(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	var a Acceptance
	if err := json.Unmarshal(raw, &a); err != nil {
		return false, nil // corrupt record is treated as missing
	}
	if a.PolicyName != policyName || a.PolicyVersion != PolicyVersion {
		return false, nil
	}
	for name, ack := range a.Acknowledgments {
		if !ack && name != "" {
			return false, nil
		}
	}
	// A complete record must acknowledge every document.
	have := map[string]bool{}
	for _, n := range a.DocumentsShown {
		have[n] = a.Acknowledgments[n]
	}
	for _, name := range AllDocNames() {
		if !have[name] {
			return false, nil
		}
	}
	return true, nil
}

func writeRecord(path string, acks map[string]bool) error {
	a := Acceptance{
		PolicyName:      policyName,
		PolicyVersion:   PolicyVersion,
		AcceptedAt:      time.Now().UTC(),
		DocumentsShown:  AllDocNames(),
		Acknowledgments: acks,
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func prompt(scanner *bufio.Scanner) (string, error) {
	fmt.Print("  > ")
	if !scanner.Scan() {
		return "", scanner.Err()
	}
	return scanner.Text(), nil
}

func interact() error {
	path := RecordPath()
	for {
		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════════")
		fmt.Println("                  GNULTE-GO FIRST RUN")
		fmt.Println("════════════════════════════════════════════════════════")
		fmt.Print(notice)
		for i, d := range docs {
			fmt.Printf("  [%d] %s\n", i+1, d.Name)
		}
		fmt.Println()
		fmt.Println("  Shortcut: type  I AGREE  to accept these documents immediately.")
		fmt.Print("  Type 'I AGREE' to accept, or press Enter to review each one (Q quits): ")

		scanner := bufio.NewScanner(os.Stdin)
		var line string
		if !scanner.Scan() {
			return errors.New("no input (non-interactive run). Refusing to proceed.")
		}
		line = strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(strings.Join(strings.Fields(line), ""))

		switch upper {
		case "Q":
			fmt.Println("Exiting. GNULTE-GO will require this review on next launch.")
			return errors.New("quit before acceptance")
		case "IAGREE":
			if err := writeRecord(path, fullAck()); err != nil {
				return err
			}
			confirm()
			return nil
		}

		// Full document-by-document review.
		fmt.Println()
		i := 0
		acks := map[string]bool{}
		for i < len(docs) {
			d := docs[i]
			fmt.Println("════════════════════════════════════════════════════════")
			fmt.Printf("  DOCUMENT [%d/%d]: %s\n", i+1, len(docs), d.Name)
			fmt.Println("════════════════════════════════════════════════════════")
			fmt.Println(d.Text)
			fmt.Println()
			fmt.Print("  Choice: [R] restart  [C] continue to acknowledgment  [Q] quit: ")
			if !scanner.Scan() {
				return errors.New("input closed during review")
			}
			switch strings.ToUpper(scanner.Text()) {
			case "R":
				continue
			case "Q":
				fmt.Println("Review stopped. Nothing was recorded.")
				return errors.New("quit during review")
			}
			fmt.Print("  I have reviewed this document. [y/N]: ")
			if !scanner.Scan() {
				return errors.New("input closed during acknowledgment")
			}
			switch strings.ToUpper(scanner.Text()) {
			case "Y":
				acks[d.Name] = true
				i++
			default:
				fmt.Printf("Not acknowledged for %s. Nothing was recorded.\n", d.Name)
				return errors.New("review not acknowledged")
			}
		}
		if err := writeRecord(path, acks); err != nil {
			return err
		}
		confirm()
		return nil
	}
}

func fullAck() map[string]bool {
	m := map[string]bool{}
	for _, d := range docs {
		m[d.Name] = true
	}
	return m
}

func confirm() {
	fmt.Println()
	fmt.Println("You have been shown the required documents and acknowledged the")
	fmt.Println("safety and authorization requirements.")
	fmt.Println("This record cannot prove you read the documents, and it does not")
	fmt.Println("make any unauthorized activity lawful.")
	fmt.Println()
}

// EnsureAccepted runs the gate unless a current, complete record exists.
// If stdin is not a terminal it refuses rather than silently bypassing.
func EnsureAccepted() error {
	path := RecordPath()
	ok, err := Valid(path)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		return errors.New("first-run safety acknowledgment must be completed from an interactive terminal; refusing to run")
	}
	return interact()
}

// ShowDocs prints the embedded documents and exits (the --docs flag).
func ShowDocs(names []string) {
	for _, n := range names {
		fmt.Println("════════════════════════════════════════════════════════")
		fmt.Printf("  %s\n", n)
		fmt.Println("════════════════════════════════════════════════════════")
		fmt.Println(DocText(n))
		fmt.Println()
	}
}

// Reset removes the acceptance record (used by --reset-safety for testing).
func Reset() error {
	path := RecordPath()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("GNULTE-GO acceptance record removed. The gate will run again.")
	return nil
}
