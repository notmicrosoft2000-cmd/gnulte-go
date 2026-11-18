// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/history"
)

// TestTrendSectionHTML checks the report's 7-day board renders a row per host
// with bars, uptime and a score, drawn purely from the timeline store.
func TestTrendSectionHTML(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)
	hist := []history.Entry{
		{Kind: history.KindSnapshot, TS: now.AddDate(0, 0, -3).Format(time.RFC3339), IP: "10.0.0.1", AvgMS: 20, P95MS: 30, UpSec: 3600},
		{Kind: history.KindSnapshot, TS: now.AddDate(0, 0, -2).Format(time.RFC3339), IP: "10.0.0.1", AvgMS: 40, P95MS: 60, UpSec: 3600},
		{Kind: history.KindDown, TS: now.AddDate(0, 0, -2).Add(time.Hour).Format(time.RFC3339), IP: "10.0.0.1"},
		{Kind: history.KindSnapshot, TS: now.AddDate(0, 0, -1).Format(time.RFC3339), IP: "10.0.0.1", AvgMS: 25, P95MS: 28, UpSec: 7200},
	}
	sess := &lanSession{
		hosts: []string{"10.0.0.1"},
		info:  map[string]hostInfo{"10.0.0.1": {IP: "10.0.0.1", Host: "laptop"}},
		hist:  hist,
		end:   now,
		iv:    1,
	}
	html := trendSection(sess)
	for _, want := range []string{"7-day trend", "10.0.0.1", "laptop", "class=bars", "pill", "Health"} {
		if !strings.Contains(html, want) {
			t.Fatalf("trend section missing %q:\n%s", want, clip(html))
		}
	}
	// The busiest day is the tallest bar; empty days are 2px stubs. Anchor on
	// the rect form ("rx=2") so the SVG root's height attribute cannot satisfy
	// the check.
	if !strings.Contains(html, "height=34 rx=2") {
		t.Fatalf("busiest day should fill the chart height:\n%s", clip(html))
	}
	if !strings.Contains(html, "height=2 rx=2") {
		t.Fatalf("empty days should be faint stubs:\n%s", clip(html))
	}
}

// TestTrendSectionEmpty explains itself rather than rendering an empty table.
func TestTrendSectionEmpty(t *testing.T) {
	sess := &lanSession{
		hosts: []string{"10.0.0.1"},
		info:  map[string]hostInfo{},
		end:   time.Now(),
		iv:    1,
	}
	if html := trendSection(sess); !strings.Contains(html, "No timeline yet") {
		t.Fatalf("empty trend section should explain itself:\n%s", clip(html))
	}
}

func TestAggregateDays(t *testing.T) {
	days := []history.Day{
		{Date: "2026-09-30", AvgMS: 20, P95MS: 30, UpSec: 100, Sessions: 1, Loss: 1},
		{Date: "2026-10-01", AvgMS: 40, P95MS: 60, UpSec: 200, Downs: 2, Sessions: 2, Loss: 4},
		{Date: "2026-10-02", AvgMS: 0, P95MS: 0, Sessions: 0},
	}
	avg, p95, loss, sessions, churn := aggregateDays(days)
	// Session-weighted: (20*1 + 40*2)/3 = 33; loss (1*1 + 4*2)/3 = 3.
	if avg != 33 || p95 != 60 || loss != 3 || sessions != 3 || churn != 2 {
		t.Fatalf("aggregateDays = avg %d p95 %d loss %v sessions %d churn %d", avg, p95, loss, sessions, churn)
	}
	if got := baselineDay(days); got != 20 {
		t.Fatalf("baselineDay = %d, want the first real latency (20)", got)
	}
	if got := baselineDay(nil); got != 0 {
		t.Fatalf("baselineDay(nil) = %d, want 0", got)
	}
	if got := upSum(days); got != 300 {
		t.Fatalf("upSum = %d, want 300", got)
	}
}

func TestFmtUptime(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0s"}, {45, "45s"}, {60, "1m"}, {3599, "59m"}, {3600, "1h00m"}, {7380, "2h03m"}, {-4, "0s"},
	}
	for _, c := range cases {
		if got := fmtUptime(c.in); got != c.want {
			t.Errorf("fmtUptime(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHealthBadgeClasses(t *testing.T) {
	cases := []struct {
		score int
		cls   string
	}{
		{95, "u"}, {70, "u"}, {69, "d"}, {40, "d"}, {39, "x"}, {0, "x"},
	}
	for _, c := range cases {
		got := healthBadge(c.score, "label")
		if !strings.Contains(got, "pill "+c.cls) || !strings.Contains(got, "label") {
			t.Errorf("healthBadge(%d) = %q, want class %q", c.score, got, c.cls)
		}
	}
}

// TestDayBarsSVGScales pins the bar geometry: one rect per day, the peak day
// at full height, and empty days as stubs.
func TestDayBarsSVGScales(t *testing.T) {
	days := []history.Day{
		{Date: "d1", AvgMS: 10, Sessions: 1},
		{Date: "d2", AvgMS: 40, Sessions: 1},
		{Date: "d3", Sessions: 0},
	}
	svg := dayBarsSVG(days, 30)
	if strings.Count(svg, "<rect") != 3 {
		t.Fatalf("want one rect per day:\n%s", svg)
	}
	if !strings.Contains(svg, `height=30 rx=2`) {
		t.Fatalf("peak day should be 30px:\n%s", svg)
	}
	if !strings.Contains(svg, `class="bar bar-empty"`) {
		t.Fatalf("empty day should be a stub:\n%s", svg)
	}
}
