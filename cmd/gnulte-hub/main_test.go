package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gnulte-go/internal/doctor"
	"gnulte-go/internal/settings"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(out)
}

func TestHubScreenCopy(t *testing.T) {
	if h1Title != "GNULTE — what do you want to do?" ||
		h1Context != "Nothing starts until you choose. Tools run in this terminal and ask for root only when they need it." ||
		h1Note != "Detailed controls are available on the next step. Direct values never require them." ||
		h1Foot != "↑/↓ choose   Enter run   number jump   q quit" {
		t.Fatalf("H1 copy drifted: %q / %q / %q / %q", h1Title, h1Context, h1Note, h1Foot)
	}
	if h2Title != "Detailed controls?" || h2Help != "Detailed adds session controls. It does not hide direct value entry." ||
		h2Foot != "↑/↓ choose   Enter continue   number jump   Esc back" {
		t.Fatalf("H2 copy drifted: %q / %q / %q", h2Title, h2Help, h2Foot)
	}
	if h3Title != "How slow should it feel?" || h3Help != "Presets set latency, jitter, loss, duplication, reorder and bandwidth." ||
		h3Foot != "↑/↓ choose   Enter continue   number jump   Esc back" {
		t.Fatalf("H3 copy drifted: %q / %q / %q", h3Title, h3Help, h3Foot)
	}

	wantLabels := []string{
		"Test a connection", "Check this machine", "Find devices",
		"See connected devices", "Watch live traffic", "Wi-Fi tools",
		"Open reports", "Read the safety rules", "Check for updates now", "Quit",
	}
	wantDetails := []string{
		"pick a device, then shape its traffic", "is everything ready?",
		"sweep the network", "saved inventory", "seven-screen live monitor",
		"authorised deauth testing", "list, merge and compare", "before you begin",
		"see whether a newer release is available", "",
	}
	available := make([]bool, len(wantLabels))
	for i := range available {
		available[i] = true
	}
	items := menuItems(actions(), available)
	if len(items) != len(wantLabels) {
		t.Fatalf("H1 has %d rows, want %d", len(items), len(wantLabels))
	}
	for i, item := range items {
		if item.Label != wantLabels[i] || item.Detail != wantDetails[i] {
			t.Errorf("H1 row %d = (%q, %q), want (%q, %q)", i+1,
				item.Label, item.Detail, wantLabels[i], wantDetails[i])
		}
	}
}

func TestDetailedAndShapingSteps(t *testing.T) {
	items := detailedItems()
	if len(items) != 2 || items[0].Label != "Standard" || items[0].Detail != "presets and direct values" ||
		items[1].Label != "Detailed" || items[1].Detail != "extra session controls" {
		t.Fatalf("H2 rows = %+v", items)
	}
	if got := detailedOptions(false).Selected; got != 0 {
		t.Errorf("H2 default selection = %d, want 0", got)
	}
	if got := detailedOptions(true).Selected; got != 1 {
		t.Errorf("H2 preselected Detailed = %d, want 1", got)
	}
	if got := detailedOptions(true).Note; got != h2Help {
		t.Errorf("H2 help = %q, want %q", got, h2Help)
	}

	rows := shapingItems()
	want := []struct{ label, detail, profile string }{
		{"A little laggy", "small stutter, still usable", "cellular"},
		{"Video calls break up", "choppy voice and picture", "voip"},
		{"Web pages crawl", "slow browsing", "web"},
		{"Almost offline", "very hard to use", "extreme"},
		{"Let me choose numbers", "set exact values", ""},
	}
	if len(rows) != len(want) {
		t.Fatalf("H3 has %d rows, want %d", len(rows), len(want))
	}
	for i, row := range rows {
		if row.Label != want[i].label || row.Detail != want[i].detail {
			t.Errorf("H3 row %d = (%q, %q), want (%q, %q)", i+1,
				row.Label, row.Detail, want[i].label, want[i].detail)
		}
		if got := profileForShapingIndex(i); got != want[i].profile {
			t.Errorf("profile for H3 row %d = %q, want %q", i+1, got, want[i].profile)
		}
	}
	if got := shapingOptions().Note; got != h3Help {
		t.Errorf("H3 help = %q, want %q", got, h3Help)
	}
}

func TestDirectParams(t *testing.T) {
	var values shapingValues
	out := captureStdout(t, func() {
		got, ok := directParams(strings.NewReader("300\n30\n0\n7\n10\nnope\n60\n"))
		if !ok {
			t.Fatal("directParams reported abort")
		}
		values = got
	})
	want := shapingValues{latency: 300, jitter: 30, loss: 0, duplicate: 7, reorder: 10, bandwidth: 0, duration: 60}
	if values != want {
		t.Errorf("directParams = %+v, want %+v", values, want)
	}
	for _, part := range []string{
		"Parameter Configuration:  Enter keeps current values.",
		"Latency (ms) [0]:", "Jitter (ms) [0]:", "Loss (%) [0]:",
		"Duplicate (%) [0]:", "Reorder (%) [0]:", "Bandwidth (kbps) [0]:",
		"Duration (s) [0]:", "ignoring non-numeric value",
	} {
		if !strings.Contains(out, part) {
			t.Errorf("H4 output missing %q: %q", part, out)
		}
	}
	if _, ok := directParams(strings.NewReader("1\n")); ok {
		t.Error("Ctrl-D/EOF in H4 must abort")
	}
	captureStdout(t, func() {
		blank, ok := directParams(strings.NewReader("\n\n\n\n\n\n\n"))
		if !ok || blank != (shapingValues{}) {
			t.Errorf("blank H4 answers = (%+v, %v), want all defaults", blank, ok)
		}
	})
}

func TestShapingLaunchArgs(t *testing.T) {
	cfg := settings.Default()
	values := shapingValues{latency: 300, jitter: 30, loss: 0, duplicate: 0, reorder: 0, bandwidth: 0, duration: 60}
	direct := []string{
		"--latency", "300", "--jitter", "30", "--loss", "0",
		"--duplicate", "0", "--reorder", "0", "--bandwidth", "0",
		"--duration", "60",
	}

	got := shapingLaunchArgs(4, values, nil, cfg)
	want := append(append([]string{}, direct...), "--interval", "1", "--sound", "--from-hub")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("standard direct args = %q, want %q", got, want)
	}

	offCfg := cfg
	offCfg.Beeps = false
	got = shapingLaunchArgs(4, values, nil, offCfg)
	want = append(append([]string{}, direct...), "--interval", "1", "--no-sound", "--from-hub")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("standard direct args with beeps off = %q, want %q", got, want)
	}

	got = shapingLaunchArgs(0, values, nil, cfg)
	want = []string{"--profile", "cellular", "--from-hub"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("standard preset args = %q, want %q", got, want)
	}

	ctrl := sessionControls{beep: true, interval: 2, echo: false}
	got = shapingLaunchArgs(0, values, &ctrl, cfg)
	want = []string{"--profile", "cellular", "--interval", "2", "--sound", "--no-echo-commands", "--from-hub"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detailed preset args = %q, want %q", got, want)
	}

	ctrl.echo = true
	got = shapingLaunchArgs(4, values, &ctrl, cfg)
	want = append(append([]string{}, direct...), "--interval", "2", "--sound", "--echo-commands", "--from-hub")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detailed direct args = %q, want %q", got, want)
	}
	if n := strings.Count(strings.Join(got, " "), "--interval"); n != 1 {
		t.Errorf("detailed direct args carry %d interval flags, want 1: %q", n, got)
	}
}

func TestActions(t *testing.T) {
	list := actions()
	if len(list) < 8 {
		t.Fatalf("only %d menu actions", len(list))
	}
	if list[len(list)-1].Binary != "" {
		t.Fatal("the last action must be Quit")
	}
	want := map[string]bool{
		"gnulte": false, "gnulte-quicksum": false, "gnulte-scan": false,
		"gnulte-inventory": false, "gnulte-watch": false, "gnulte-wifi": false,
		"gnulte-report": false,
	}
	foundUpdate := false
	for _, a := range list {
		if a.Binary == "" {
			continue
		}
		if a.Binary == updateAction {
			foundUpdate = true
			continue
		}
		if _, ok := want[a.Binary]; !ok {
			t.Errorf("unexpected binary %q in menu", a.Binary)
		}
		want[a.Binary] = true
	}
	if !foundUpdate {
		t.Error("menu has no Check for updates now row")
	}
	for name, found := range want {
		if !found {
			t.Errorf("menu has no action for %s", name)
		}
	}
}

func TestFindBinaryPrefersSibling(t *testing.T) {
	sibling := t.TempDir()
	onPath := t.TempDir()
	for _, dir := range []string{sibling, onPath} {
		if err := os.WriteFile(filepath.Join(dir, "gnulte"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", onPath)
	got := findBinary(sibling, "gnulte")
	if want := filepath.Join(sibling, "gnulte"); got != want {
		t.Errorf("findBinary = %q, want sibling %q", got, want)
	}
}

func TestFindBinaryFallsBackToPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gnulte-scan"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got := findBinary(t.TempDir(), "gnulte-scan")
	if want := filepath.Join(dir, "gnulte-scan"); got != want {
		t.Errorf("findBinary = %q, want PATH result %q", got, want)
	}
	if got := findBinary(t.TempDir(), "no-such-tool"); got != "" {
		t.Errorf("findBinary for missing tool = %q, want empty", got)
	}
}

func TestMenuItemsMarkMissing(t *testing.T) {
	list := actions()
	available := make([]bool, len(list))
	for i := range available {
		available[i] = true
	}
	available[0] = false
	items := menuItems(list, available)
	if items[0].Detail != "not installed" {
		t.Errorf("missing tool detail = %q", items[0].Detail)
	}
	if items[1].Detail != list[1].Detail {
		t.Errorf("available tool detail = %q, want %q", items[1].Detail, list[1].Detail)
	}
}

func TestUpdateMenuRowIsAlwaysAvailable(t *testing.T) {
	list := actions()
	var row *action
	for i := range list {
		if list[i].Binary == updateAction {
			row = &list[i]
		}
	}
	if row == nil {
		t.Fatal("no update action")
	}
	if row.Label != "Check for updates now" || row.Detail != "see whether a newer release is available" {
		t.Fatalf("update row = %+v", row)
	}
	if !actionAvailable(t.TempDir(), *row) {
		t.Fatal("the built-in update row must not depend on a binary on disk")
	}

	available := make([]bool, len(list))
	items := menuItems(list, available)
	idx := -1
	for i, a := range list {
		if a.Binary == updateAction {
			idx = i
		}
	}
	if got := items[idx].Detail; got != row.Detail {
		t.Errorf("update row detail = %q, want %q (not 'not installed')", got, row.Detail)
	}
}

func TestPrintDoctorReport(t *testing.T) {
	checks := []doctor.Check{
		{Name: "tc", Status: doctor.Pass, Detail: "impair and shape traffic"},
		{Name: "privileges", Status: doctor.Warn, Detail: "euid 1000", Hint: "use sudo"},
		{Name: "iptables", Status: doctor.Fail, Detail: "not found in PATH", Hint: "apt install iptables"},
	}
	var out bytes.Buffer
	printDoctorReport(&out, checks)
	text := out.String()
	for _, token := range []string{"PASS", "WARN", "FAIL", "fix: use sudo", "1 passed, 1 warning(s), 1 failure(s)"} {
		if !strings.Contains(text, token) {
			t.Errorf("doctor report missing %q: %q", token, text)
		}
	}
}

func TestRunCLIDoctor(t *testing.T) {
	var out, errOut bytes.Buffer
	handled, code := runCLI([]string{"doctor"}, &out, &errOut)
	if !handled {
		t.Fatal("doctor was not handled")
	}
	if code != 0 && code != 1 {
		t.Fatalf("doctor exit code = %d, want 0 or 1", code)
	}
	if !strings.Contains(out.String(), "GNULTE DOCTOR") || !strings.Contains(out.String(), "passed,") {
		t.Fatalf("doctor output = %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("unexpected stderr %q", errOut.String())
	}
}

func TestRunCLICompletions(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var out, errOut bytes.Buffer
			handled, code := runCLI([]string{"--completions", shell}, &out, &errOut)
			if !handled || code != 0 {
				t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
			}
			if !strings.Contains(out.String(), "gnulte-hub") {
				t.Error("completion script has no hub entry")
			}
		})
	}

	t.Run("equals form", func(t *testing.T) {
		var out, errOut bytes.Buffer
		handled, code := runCLI([]string{"--completions=zsh"}, &out, &errOut)
		if !handled || code != 0 || !strings.HasPrefix(out.String(), "#compdef ") {
			t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
		}
	})

	for _, args := range [][]string{{"--completions"}, {"--completions", "powershell"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			handled, code := runCLI(args, &out, &errOut)
			if !handled || code != 2 {
				t.Fatalf("handled=%v code=%d, want true/2", handled, code)
			}
			if out.Len() != 0 || !strings.Contains(errOut.String(), "gnulte-hub:") {
				t.Fatalf("out=%q err=%q", out.String(), errOut.String())
			}
		})
	}
}

func TestUsageMentionsNewFlags(t *testing.T) {
	out := captureStdout(t, usage)
	for _, token := range []string{"--version", "doctor", "--completions", "--check-update"} {
		if !strings.Contains(out, token) {
			t.Errorf("usage missing %q: %q", token, out)
		}
	}
}
