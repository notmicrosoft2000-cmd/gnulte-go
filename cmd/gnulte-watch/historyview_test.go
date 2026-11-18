// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/traffic"
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
