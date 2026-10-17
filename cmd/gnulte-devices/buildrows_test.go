// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gnulte-go/internal/discover"
	"gnulte-go/internal/netutil"
)

// buildRows fans out over the live list with 8 goroutines that all call add(),
// which touched the `seen` dedupe map with no lock while the `rows` slice right
// beside it *was* locked. Go aborts the process with "concurrent map writes"
// (uncatchable) as soon as a live host is not already an ARP neighbour.
// Run with -race; the assertion also checks dedupe still works.
func TestBuildRowsConcurrentMapWrite(t *testing.T) {
	live := make([]string, 0, 40)
	for i := 1; i <= 40; i++ {
		live = append(live, fmt.Sprintf("192.0.2.%d", i))
	}
	cfg := netutil.Config{SelfIP: "192.0.2.1", Gateway: "192.0.2.254"}
	// A short-lived context keeps the test quick: buildRows' trailing
	// hostname enrichment does mDNS lookups, but the racy fan-out (the code
	// under test) runs before it.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	rows := buildRows(ctx, live, map[string]string{}, cfg, true)
	if len(rows) != 40 {
		t.Errorf("got %d rows, want 40", len(rows))
	}
	// Duplicates must still be deduped (neighbours seeded + live list).
	dup := buildRows(ctx, append(live, live...), map[string]string{"192.0.2.5": "aa:bb:cc:dd:ee:ff"}, cfg, true)
	if len(dup) != 40 {
		t.Errorf("dedupe broken: got %d rows for 40 unique of 80 inputs", len(dup))
	}
}

// TestBuildRowsSkipsEnrichUnderNoHostnames: with --no-hostnames buildRows must
// not run the trailing enrichment pass. A package seam records whether it was
// called, so the assertion does not depend on a name actually resolving.
func TestBuildRowsSkipsEnrichUnderNoHostnames(t *testing.T) {
	old := enrichHostnames
	called := 0
	enrichHostnames = func(context.Context, []discover.Row) { called++ }
	t.Cleanup(func() { enrichHostnames = old })

	cfg := netutil.Config{SelfIP: "192.0.2.1", Gateway: "192.0.2.254"}
	// Empty inputs keep the test off the network; only the gate is under test.
	buildRows(context.Background(), nil, map[string]string{}, cfg, true)
	if called != 0 {
		t.Fatalf("enrichment ran %d time(s) under --no-hostnames", called)
	}
	buildRows(context.Background(), nil, map[string]string{}, cfg, false)
	if called != 1 {
		t.Fatalf("enrichment ran %d time(s) without --no-hostnames, want 1", called)
	}
}

// TestEmitExportWritesToWriter pins the contract that the export is written to
// the writer it is handed. main hands it the -o file when one is set; if that
// wiring regresses to os.Stdout, -o silently creates an empty file.
func TestEmitExportWritesToWriter(t *testing.T) {
	rows := []discover.Row{{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"}}

	var b bytes.Buffer
	if err := emitExport(&b, rows, true, false, false); err != nil {
		t.Fatalf("emitExport json: %v", err)
	}
	if !strings.Contains(b.String(), "\"ip\": \"10.0.0.1\"") {
		t.Errorf("json not written to the provided writer:\n%s", b.String())
	}

	b.Reset()
	if err := emitExport(&b, rows, false, true, false); err != nil {
		t.Fatalf("emitExport yaml: %v", err)
	}
	if !strings.Contains(b.String(), "hosts:") {
		t.Errorf("yaml not written to the provided writer:\n%s", b.String())
	}

	b.Reset()
	if err := emitExport(&b, rows, false, false, true); err != nil {
		t.Fatalf("emitExport csv: %v", err)
	}
	if !strings.Contains(b.String(), "ip,mac") {
		t.Errorf("csv not written to the provided writer:\n%s", b.String())
	}

	b.Reset()
	if err := emitExport(&b, rows, false, false, false); err != nil {
		t.Fatalf("emitExport none: %v", err)
	}
	if b.Len() != 0 {
		t.Errorf("no export requested but wrote %q", b.String())
	}
}
