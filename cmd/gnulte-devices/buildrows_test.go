// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

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
