package safety

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidRejectsMissing(t *testing.T) {
	dir := t.TempDir()
	ok, err := Valid(filepath.Join(dir, "acceptance.json"))
	if err != nil || ok {
		t.Fatalf("missing record: ok=%v err=%v (want false, nil)", ok, err)
	}
}

func TestValidRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "acceptance.json")
	if err := os.WriteFile(p, []byte("not json{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := Valid(p)
	if err != nil || ok {
		t.Fatalf("corrupt record: ok=%v err=%v (want false, nil)", ok, err)
	}
}

func TestValidRejectsPartialAcks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "acceptance.json")
	data := `{"policy_name":"GNULTE-GO","policy_version":1,"accepted_at":"2026-09-12T00:00:00Z",
"documents_shown":["LICENSE"],"acknowledgments":{"LICENSE":true}}`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, _ := Valid(p)
	if ok {
		t.Fatal("partial acknowledgment should be invalid")
	}
}

func TestValidRequiresAllDocs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "acceptance.json")
	data := `{"policy_name":"GNULTE-GO","policy_version":1,"accepted_at":"2026-09-12T00:00:00Z",
"documents_shown":["LICENSE"],"acknowledgments":{"LICENSE":true}}`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	// A record acknowledging only LICENSE must be invalid (all docs required).
	if ok, _ := Valid(p); ok {
		t.Fatal("record acknowledging only LICENSE must be invalid (all docs required)")
	}
}

func TestValidAcceptsComplete(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "acceptance.json")
	if err := writeRecord(p, fullAck()); err != nil {
		t.Fatal(err)
	}
	if ok, err := Valid(p); !ok || err != nil {
		t.Fatalf("complete record: ok=%v err=%v (want true, nil)", ok, err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("acceptance file perms = %o, want 600", fi.Mode().Perm())
	}
}

func TestShowDocsCoversEverything(t *testing.T) {
	for _, name := range AllDocNames() {
		if DocText(name) == "" {
			t.Errorf("document %s has no embedded text", name)
		}
	}
}
