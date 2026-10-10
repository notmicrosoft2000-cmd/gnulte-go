package inventory

import (
	"testing"
	"time"
)

func eqInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPortDelta(t *testing.T) {
	ap, cl := PortDelta([]int{22, 80, 443}, []int{22, 443, 8080})
	if !eqInts(ap, []int{8080}) {
		t.Errorf("appeared = %v, want [8080]", ap)
	}
	if !eqInts(cl, []int{80}) {
		t.Errorf("closed = %v, want [80]", cl)
	}
	// Duplicates and ordering must not affect the result.
	if ap, cl := PortDelta([]int{80, 80, 22}, []int{22, 80}); len(ap) != 0 || len(cl) != 0 {
		t.Errorf("no-op delta = %v/%v", ap, cl)
	}
	if ap, cl := PortDelta(nil, []int{443}); !eqInts(ap, []int{443}) || len(cl) != 0 {
		t.Errorf("baseline delta = %v/%v", ap, cl)
	}
}

func TestRememberToAccumulatesAwakeAndPorts(t *testing.T) {
	path := saveToTmp(t)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	recs, changes, err := RememberTo(path, nil, []Sighting{{
		Record:  Record{IP: "192.168.99.10", MAC: "aa:bb:cc:dd:ee:01", Vendor: "Synology", Host: "nas", Kind: "NAS"},
		Ports:   []int{22, 80},
		Banners: []string{"22 (ssh): SSH-2.0-x"},
		OS:      "Linux",
	}}, t0)
	if err != nil {
		t.Fatalf("RememberTo: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("first sighting raised churn: %+v", changes)
	}
	if len(recs) != 1 || recs[0].Sightings != 1 || recs[0].AwakeSec != 0 {
		t.Fatalf("bad first record: %+v", recs[0])
	}
	if !eqInts(recs[0].Ports, []int{22, 80}) || recs[0].OS != "Linux" {
		t.Fatalf("first record did not remember detail: %+v", recs[0])
	}

	// Five minutes later one port closed and another appeared.
	recs, changes, err = RememberTo(path, recs, []Sighting{{
		Record: Record{IP: "192.168.99.10", Host: "nas"},
		Ports:  []int{22, 443},
	}}, t0.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("RememberTo: %v", err)
	}
	if len(changes) != 1 || !eqInts(changes[0].Appeared, []int{443}) || !eqInts(changes[0].Closed, []int{80}) {
		t.Fatalf("port churn = %+v", changes)
	}
	if recs[0].Sightings != 2 || recs[0].AwakeSec != 300 {
		t.Errorf("after second sighting: sightings=%d awake=%d, want 2/300", recs[0].Sightings, recs[0].AwakeSec)
	}
	if !eqInts(recs[0].Ports, []int{22, 443}) {
		t.Errorf("ports not refreshed: %v", recs[0].Ports)
	}

	// A long absence is not credited as awake time and, with no movement,
	// raises no churn.
	recs, changes, err = RememberTo(path, recs, []Sighting{{
		Record: Record{IP: "192.168.99.10", Host: "nas"},
		Ports:  []int{22, 443},
	}}, t0.Add(40*time.Minute))
	if err != nil {
		t.Fatalf("RememberTo: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("steady ports raised churn: %+v", changes)
	}
	if recs[0].AwakeSec != 300 || recs[0].Sightings != 3 {
		t.Errorf("after absence: awake=%d sightings=%d, want 300/3", recs[0].AwakeSec, recs[0].Sightings)
	}

	// The memory must survive a round-trip through the store file.
	loaded, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Sightings != 3 || loaded[0].AwakeSec != 300 || !eqInts(loaded[0].Ports, []int{22, 443}) {
		t.Fatalf("persisted record = %+v", loaded)
	}
}

func TestRememberToBaselineSilentForARPHost(t *testing.T) {
	path := saveToTmp(t)
	// A gnulte-lan record carries identity but no port set.
	if err := SaveTo(path, []Record{{IP: "192.168.99.20", MAC: "aa:bb:cc:dd:ee:02", Kind: "Phone"}}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	recs, _ := LoadFrom(path)
	_, changes, err := RememberTo(path, recs, []Sighting{{
		Record: Record{IP: "192.168.99.20", Host: "phone"},
		Ports:  []int{80},
	}}, time.Now())
	if err != nil {
		t.Fatalf("RememberTo: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("first deep scan of an ARP-only host must establish a baseline silently, got %+v", changes)
	}
	loaded, _ := LoadFrom(path)
	if !eqInts(loaded[0].Ports, []int{80}) {
		t.Errorf("baseline ports not stored: %v", loaded[0].Ports)
	}
}

func TestFormatAwake(t *testing.T) {
	for _, tc := range []struct {
		sec  int
		want string
	}{
		{0, ""},
		{-5, ""},
		{45 * 60, "45m"},
		{6*3600 + 12*60, "6h12m"},
		{3*86400 + 2*3600, "3d2h"},
	} {
		if got := FormatAwake(tc.sec); got != tc.want {
			t.Errorf("FormatAwake(%d) = %q, want %q", tc.sec, got, tc.want)
		}
	}
}
