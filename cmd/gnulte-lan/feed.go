// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"gnulte-go/internal/history"
	"gnulte-go/internal/traffic"
)

// The --json feed is a JSON-lines stream on stdout: one baseline object when
// the watch starts, one tick object per interval, and one alert object on each
// debounced up/down transition. Everything human stays on stderr so
// `gnulte-lan --json | jq` sees nothing but the feed. The record shapes are
// plain structs so a test can marshal one and pin the schema.

type feedBaseline struct {
	Kind     string `json:"kind"`
	TS       string `json:"ts"`
	Iface    string `json:"iface"`
	Hosts    int    `json:"hosts"`
	Interval int    `json:"interval_s"`
}

type feedHost struct {
	IP      string  `json:"ip"`
	Name    string  `json:"name,omitempty"`
	RTTMS   int     `json:"rtt_ms"`
	LossPct float64 `json:"loss_pct"`
	DownBps int64   `json:"down_bps"`
	UpBps   int64   `json:"up_bps"`
	Alarm   bool    `json:"alarm"`
}

type feedTick struct {
	Kind   string     `json:"kind"`
	TS     string     `json:"ts"`
	Up     int        `json:"up"`
	Alarms int        `json:"alarms"`
	Hosts  []feedHost `json:"hosts"`
}

type feedAlert struct {
	Kind  string `json:"kind"`
	TS    string `json:"ts"`
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"`
	Event string `json:"event"` // "up" | "down"
}

// writeJSON marshals one feed record to stdout as a single JSON line. The
// record structs cannot fail to marshal, but keeping the helper here means the
// stream format lives in exactly one place.
func writeJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Println(string(b))
}

func newFeedBaseline(iface string, hosts, interval int, now time.Time) feedBaseline {
	return feedBaseline{
		Kind:     "baseline",
		TS:       now.UTC().Format(time.RFC3339),
		Iface:    iface,
		Hosts:    hosts,
		Interval: interval,
	}
}

func newFeedTick(hosts []string, stats map[string]*hostStat, rates map[string]traffic.Rate,
	info map[string]hostInfo, iv int, now time.Time) feedTick {

	rows := make([]feedHost, 0, len(hosts))
	up, alarms := 0, 0
	for _, ip := range hosts {
		st := stats[ip]
		r := rates[ip]
		// Count "up" only after a real success, and mirror the header's -2
		// sentinel for a host that has not been probed yet.
		if st.ping.count > 0 {
			up++
		}
		rtt := st.ping.last
		if st.ping.count+st.ping.drops == 0 {
			rtt = -2
		}
		if st.alarm {
			alarms++
		}
		rows = append(rows, feedHost{
			IP:      ip,
			Name:    nameOf(info[ip]),
			RTTMS:   rtt,
			LossPct: st.ping.loss(),
			DownBps: bps(r.RXBytes, iv),
			UpBps:   bps(r.TXBytes, iv),
			Alarm:   st.alarm,
		})
	}
	return feedTick{
		Kind:   "tick",
		TS:     now.UTC().Format(time.RFC3339),
		Up:     up,
		Alarms: alarms,
		Hosts:  rows,
	}
}

func newFeedAlert(ev watchEvent) feedAlert {
	event := "down"
	if ev.up {
		event = "up"
	}
	return feedAlert{
		Kind:  "alert",
		TS:    ev.when.UTC().Format(time.RFC3339),
		IP:    ev.ip,
		Name:  ev.name,
		Event: event,
	}
}

// watchEvents converts stored history records (newest last) into the lighter
// view-facing events the history screen lists.
func watchEvents(entries []history.Entry) []watchEvent {
	out := make([]watchEvent, 0, len(entries))
	for _, e := range entries {
		if e.Kind != history.KindUp && e.Kind != history.KindDown {
			continue
		}
		when, ok := e.Time()
		if !ok {
			continue
		}
		out = append(out, watchEvent{
			when: when,
			ip:   e.IP,
			name: e.Name,
			up:   e.Kind == history.KindUp,
		})
	}
	return out
}
