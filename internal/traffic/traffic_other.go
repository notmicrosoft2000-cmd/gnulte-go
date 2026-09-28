// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

//go:build !linux

package traffic

import "errors"

// Counter is a no-op on platforms without AF_PACKET; the monitor runs its
// usual counters-free display.
type Counter struct{}

// New reports the feature as unavailable off Linux.
func New(iface string) (*Counter, error) {
	return nil, errors.New("live traffic counters are Linux-only (AF_PACKET raw sockets)")
}

// Close is a no-op.
func (c *Counter) Close() {}

// Snapshot always returns an empty set.
func (c *Counter) Snapshot() map[string]Rate {
	return map[string]Rate{}
}

// SnapshotFlows always returns an empty set.
func (c *Counter) SnapshotFlows() []Flow {
	return nil
}

// FlowTotals always returns an empty set.
func (c *Counter) FlowTotals() []Flow {
	return nil
}
