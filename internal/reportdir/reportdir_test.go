package reportdir

import (
	"path/filepath"
	"regexp"
	"testing"
)

func TestDefaultPathCountNames(t *testing.T) {
	home := t.TempDir()
	// Keep os.UserHomeDir honest for this test only.
	t.Setenv("HOME", home)

	p := DefaultPathCount(GNULTEGo, "gnulte-go-scan-report", 3)
	re := regexp.MustCompile(`^gnulte-go-scan-report-\d{8}-\d{6}-3\.html$`)
	base := filepath.Base(p)
	if !re.MatchString(base) {
		t.Fatalf("DefaultPathCount produced %q, want pattern gnulte-go-scan-report-DATE-TIME-3.html", base)
	}
	if filepath.Dir(p) != filepath.Join(home, "GNULTE Reports", string(GNULTEGo)) {
		t.Fatalf("report not placed in the hub subfolder: %s", p)
	}
}

func TestDefaultPathStillWorks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if p := DefaultPath(GnulteScan, "gnulte-scan-report"); !regexp.MustCompile(`gnulte-scan-report-\d{8}-\d{6}\.html$`).MatchString(filepath.Base(p)) {
		t.Fatalf("DefaultPath regressed: %s", p)
	}
}
