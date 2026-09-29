package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// saveToTmp writes a store through an explicit temp path so tests never touch
// the real ~/.config/gnulte-go.
func saveToTmp(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "gnulte-go", "devices.json")
}

func TestRoundTrip(t *testing.T) {
	path := saveToTmp(t)
	recs := []Record{
		{IP: "192.168.99.110", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Xiaomi", Host: "phone", Kind: "Phone"},
		{IP: "192.168.99.1", Vendor: "Frontiir", Kind: "Router/Gateway", IsSelf: false},
	}
	if err := SaveTo(path, recs); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	// The shared default path must not be hit by the explicit-path reads.
	got, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].IP != "192.168.99.1" || got[1].IP != "192.168.99.110" {
		t.Errorf("records not sorted by IP: %#v", got)
	}
	if got[1].Host != "phone" || got[1].Kind != "Phone" {
		t.Errorf("record detail lost: %#v", got[1])
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	recs, err := LoadFrom(filepath.Join(t.TempDir(), "nope", "devices.json"))
	if err != nil {
		t.Fatalf("missing store should be empty, not an error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records, want none", len(recs))
	}
}

func TestLoadMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(path); err == nil {
		t.Fatal("malformed store should error")
	} else if !strings.Contains(err.Error(), "malformed device store") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateFreshSeenAndMerge(t *testing.T) {
	path := saveToTmp(t)

	recs, msg, err := UpdateTo(nil, Record{IP: "10.0.0.5", Vendor: "ACME", Kind: "Router"}, path, "devices")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if msg == "" || !strings.Contains(msg, path) {
		t.Errorf("confirmation message missing path: %q", msg)
	}
	if len(recs) != 1 || recs[0].IP != "10.0.0.5" {
		t.Fatalf("first sighting not added: %#v", recs)
	}
	if recs[0].FirstSeen == "" || recs[0].LastSeen == "" {
		t.Fatalf("timestamps missing: %#v", recs[0])
	}
	first := recs[0].FirstSeen

	// Same IP again: no duplicate, timestamps refreshed, detail updated.
	recs, _, err = UpdateTo(recs, Record{IP: "10.0.0.5", Vendor: "ACME", Host: "core"}, path, "devices")
	if err != nil {
		t.Fatalf("Update repeat: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("repeat sighting duplicated the record: %#v", recs)
	}
	if recs[0].Host != "core" {
		t.Errorf("detail not refreshed: %#v", recs[0])
	}
	if recs[0].FirstSeen != first {
		t.Errorf("FirstSeen must survive a repeat sighting: %#v", recs[0])
	}

	// A second distinct IP appends.
	recs, _, err = UpdateTo(recs, Record{IP: "10.0.0.9", Vendor: "Self", IsSelf: true}, path, "devices")
	if err != nil {
		t.Fatalf("Update second: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if !recs[0].IsSelf && !recs[1].IsSelf {
		t.Error("IsSelf flag lost")
	}

	// The file on disk matches the in-memory store.
	disk, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(disk) != 2 {
		t.Fatalf("disk store has %d records, want 2", len(disk))
	}
}

func TestMergeListBulk(t *testing.T) {
	path := saveToTmp(t)
	existing := []Record{{IP: "10.0.0.1", Kind: "Router", FirstSeen: "old", LastSeen: "old"}}
	sightings := []Record{
		{IP: "10.0.0.1", Vendor: "ACME", Kind: "Router"}, // refresh
		{IP: "10.0.0.2", Vendor: "Xiaomi", Kind: "Phone"}, // new
		{IP: "10.0.0.3", Vendor: "Self", IsSelf: true},    // new
	}
	merged, added, err := MergeListTo(existing, path, sightings)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}
	if len(merged) != 3 {
		t.Fatalf("want 3 records, got %d", len(merged))
	}
	for _, r := range merged {
		if r.LastSeen == "" || r.LastSeen == "old" {
			t.Errorf("record %s has stale LastSeen %q", r.IP, r.LastSeen)
		}
		if r.IP == "10.0.0.1" && r.FirstSeen != "old" {
			t.Errorf("existing FirstSeen clobbered: %#v", r)
		}
	}
	if !merged[1].IsSelf && !merged[2].IsSelf {
		t.Error("IsSelf flag lost in bulk merge")
	}
}

func TestSummaryAndKinds(t *testing.T) {
	recs := []Record{
		{IP: "1.1.1.1", Kind: "Phone"},
		{IP: "2.2.2.2", Kind: "Router/Gateway"},
		{IP: "3.3.3.3"},
	}
	if k := Kinds(recs); k != "Phone, Router/Gateway" {
		t.Errorf("Kinds: %q", k)
	}
	if s := Summary(recs); s != "3 device(s) — Phone, Router/Gateway" {
		t.Errorf("Summary: %q", s)
	}
	if s := Summary(nil); s != "no saved devices yet" {
		t.Errorf("empty Summary: %q", s)
	}
}