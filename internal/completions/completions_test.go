package completions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var allBinaries = []string{
	"gnulte", "gnulte-scan", "gnulte-wifi", "gnulte-watch",
	"gnulte-inventory", "gnulte-quicksum", "gnulte-report", "gnulte-hub",
}

func TestScriptsCoverAllBinaries(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			script, err := Script(shell)
			if err != nil {
				t.Fatal(err)
			}
			if script == "" {
				t.Fatal("empty script")
			}
			for _, name := range allBinaries {
				if !strings.Contains(script, name) {
					t.Errorf("%s script is missing %s", shell, name)
				}
			}
			switch shell {
			case "bash":
				if !strings.Contains(script, "complete -F ") {
					t.Error("bash script has no complete -F registration")
				}
			case "zsh":
				if !strings.HasPrefix(script, "#compdef ") {
					t.Error("zsh script has no #compdef header")
				}
			case "fish":
				if !strings.Contains(script, "complete -c gnulte") {
					t.Error("fish script has no complete -c lines")
				}
			}
		})
	}
}

func TestScriptsCoverFlagsValuesAndSubcommands(t *testing.T) {
	longFlags := []string{
		"check-update", "settings", "docs", "reset-safety", "no-report",
		"interface", "list-profiles", "profile", "reason", "completions",
	}
	otherTokens := []string{
		"gaming", "nightmare", "leaving", "bash", "doctor", "top", "trace",
		"list", "index", "merge", "compare", "archive",
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			script, err := Script(shell)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range longFlags {
				token := "--" + name
				if shell == "fish" {
					token = "-l " + name // fish spells long options with -l
				}
				if !strings.Contains(script, token) {
					t.Errorf("%s script is missing %q", shell, token)
				}
			}
			for _, token := range otherTokens {
				if !strings.Contains(script, token) {
					t.Errorf("%s script is missing %q", shell, token)
				}
			}
		})
	}
}

func TestScriptRejectsUnknownShell(t *testing.T) {
	for _, shell := range []string{"", "powershell", "sh"} {
		script, err := Script(shell)
		if err == nil {
			t.Errorf("Script(%q) error = nil, want an error", shell)
		}
		if script != "" {
			t.Errorf("Script(%q) = %q, want empty", shell, script)
		}
	}
}

func TestScriptIncludesSavedProfiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	profileDir := filepath.Join(dir, "gnulte-go", "profiles")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "my-profile.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script, err := Script("bash")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"gaming", "nightmare", "my-profile"} {
		if !strings.Contains(script, token) {
			t.Errorf("profile %q missing from bash script", token)
		}
	}
}
