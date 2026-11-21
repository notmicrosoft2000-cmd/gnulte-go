// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
	"gnulte-go/internal/ux"
)

// TestHistoryScreenRendersAlarmsAndToday builds screen 6 with one session
// alarm and one stored transition and checks both lists, the glyphs and the
// identity labels come through.
func TestHistoryScreenRendersAlarmsAndToday(t *testing.T) {
	hosts, stats := testHosts()
	now := time.Now()
	env := watchEnv{
		nic: "wlan0", iv: 1, start: now, width: 120, hasCounter: true,
		events: []watchEvent{
			{when: now.Add(-40 * time.Second), ip: "192.168.100.40", name: "cassie-phone", up: false},
		},
		today: []watchEvent{
			{when: now.Add(-2 * time.Minute), ip: "192.168.100.207", name: "", up: true},
		},
	}
	st := &viewState{screen: scrHistory}
	out := buildView(st, hosts, nil, map[string]traffic.Rate{}, nil, nil, stats, env, 30)
	all := strings.Join(out, "\n")
	for _, want := range []string{"HISTORY", "ALARMS", "TODAY", "192.168.100.40", "cassie-phone", "192.168.100.207", "✗", "✓"} {
		if !strings.Contains(all, want) {
			t.Fatalf("history screen missing %q:\n%s", want, all)
		}
	}
	if !strings.Contains(footerHint(st), "history") {
		t.Fatalf("history footer missing: %q", footerHint(st))
	}
}

// TestHistoryScreenEmpty stays usable before any transition has happened.
func TestHistoryScreenEmpty(t *testing.T) {
	hosts, stats := testHosts()
	env := watchEnv{iv: 1, start: time.Now(), width: 100}
	st := &viewState{screen: scrHistory}
	out := buildView(st, hosts, nil, map[string]traffic.Rate{}, nil, nil, stats, env, 24)
	all := strings.Join(out, "\n")
	if !strings.Contains(all, "none yet") {
		t.Fatalf("empty history screen should explain itself:\n%s", all)
	}
}

// TestHistoryScreenBudget caps the body so a busy LAN cannot overflow a short
// terminal.
func TestHistoryScreenBudget(t *testing.T) {
	now := time.Now()
	events := make([]watchEvent, 40)
	for i := range events {
		events[i] = watchEvent{when: now.Add(-time.Duration(i) * time.Second), ip: "192.168.100.40", up: i%2 == 0}
	}
	env := watchEnv{iv: 1, start: now, width: 120, events: events, today: events}
	out := historyLines(env, 12)
	if len(out) > 12 {
		t.Fatalf("historyLines exceeded budget: %d lines", len(out))
	}
	if !strings.Contains(strings.Join(out, "\n"), "more…") {
		t.Fatalf("capped history should note hidden events:\n%s", strings.Join(out, "\n"))
	}
}

// TestScreenLabelHistory keeps the header tag stable.
func TestScreenLabelHistory(t *testing.T) {
	if got := screenLabel(scrHistory); got != "HISTORY" {
		t.Fatalf("screenLabel(scrHistory) = %q", got)
	}
}

// TestPathEventsOnlyRealTransitions pins the D1 EVENTS contract: the only
// event forms are <watchEvent.when> host <ip> up/down. No ARP redirect, netem,
// forwarding, scenario phase, optimisation language or invented timestamp may
// leak into the PATH frame.
func TestPathEventsOnlyRealTransitions(t *testing.T) {
	hosts, info, stats, env := pathTestEnv(120)
	now := time.Now()
	env.events = []watchEvent{
		{when: now.Add(-9 * time.Second), ip: "192.0.2.10", name: "phone", up: true},
		{when: now.Add(-3 * time.Second), ip: "192.0.2.11", name: "tablet", up: false},
	}
	out := buildView(&viewState{screen: scrPath}, hosts, info, nil, nil, nil, stats, env, 40)
	all := ux.StripAnsi(strings.Join(out, "\n"))
	want := map[string]bool{
		env.events[0].when.Format("15:04:05") + "  host 192.0.2.10 up":   false,
		env.events[1].when.Format("15:04:05") + "  host 192.0.2.11 down": false,
	}
	for line := range want {
		if !strings.Contains(all, line) {
			t.Errorf("PATH frame missing exact event line %q:\n%s", line, all)
		}
	}
	for _, banned := range []string{
		"ARP redirect", "netem", "tc ", "forwarding", "scenario", "phase",
		"optimis", "no transitions this session",
	} {
		if strings.Contains(strings.ToLower(all), strings.ToLower(banned)) {
			t.Errorf("PATH frame invented forbidden text %q:\n%s", banned, all)
		}
	}
	// Every timestamp in the frame must be one of the two real transitions.
	ts := regexp.MustCompile(`\d\d:\d\d:\d\d`)
	for _, line := range strings.Split(all, "\n") {
		for _, m := range ts.FindAllString(line, -1) {
			if !strings.Contains(line, m+"  host ") {
				t.Errorf("invented timestamp %q in line %q", m, line)
			}
		}
	}
}
