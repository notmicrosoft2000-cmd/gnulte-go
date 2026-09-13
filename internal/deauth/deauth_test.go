// GNULTE — network testing toolkit. Licensed under the GNU GPL version 3.

package deauth

import (
	"encoding/hex"
	"testing"
)

func TestParseMAC(t *testing.T) {
	good := []string{"00:0c:41:63:45:6a", "00-0C-41-63-45-6A", "000c4163456a", "00.0c.41.63.45.6a"}
	for _, s := range good {
		m, err := ParseMAC(s)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", s, err)
		}
		if got := m.String(); got != "00:0c:41:63:45:6a" {
			t.Errorf("ParseMAC(%q) = %s, want canonical form", s, got)
		}
	}
	bad := []string{"", "zz", "00:0c:41:63:45", "00:0c:41:63:45:6a:bb", "00:0c:41:63:45:g6"}
	for _, s := range bad {
		if _, err := ParseMAC(s); err == nil {
			t.Errorf("ParseMAC(%q) succeeded, want error", s)
		}
	}
	b, err := ParseMAC(Broadcast)
	if err != nil || !b.IsBroadcast() {
		t.Errorf("broadcast parse failed: %v", err)
	}
}

func TestFrameGolden(t *testing.T) {
	bssid, _ := ParseMAC("00:0c:41:63:45:6a")
	station, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	got := Frame(bssid, station, ReasonLeavingBSS, 0)
	if len(got) != FrameSize {
		t.Fatalf("Frame length = %d, want %d", len(got), FrameSize)
	}
	want := "0000080000000000" + // radiotap
		"c000" + "0000" + // frame control (deauth) + duration
		"aabbccddeeff" + // destination = victim
		"000c4163456a" + // source = AP BSSID
		"000c4163456a" + // BSSID = AP
		"0000" + // sequence
		"0700" // reason 7
	if hex.EncodeToString(got) != want {
		t.Errorf("Frame = %s\n want  %s", hex.EncodeToString(got), want)
	}
}

func TestFrameSourceIsBSSID(t *testing.T) {
	// The claim: DA = victim, SA = BSSID = AP, so the victim sees the router
	// as the sender.
	bssid, _ := ParseMAC("00:0c:41:63:45:6a")
	station, _ := ParseMAC("10:20:30:40:50:60")
	f := Frame(bssid, station, ReasonUnspecified, 0)
	// radiotap(8) + fc(2) + dur(2) -> DA at [12:18], SA at [18:24].
	da, sa, bss := f[12:18], f[18:24], f[24:30]
	if hex.EncodeToString(da) != hex.EncodeToString(station.Addr[:]) {
		t.Errorf("DA = %02x, want victim", da)
	}
	if hex.EncodeToString(sa) != hex.EncodeToString(bssid.Addr[:]) {
		t.Errorf("SA = %02x, want AP BSSID", sa)
	}
	if hex.EncodeToString(bss) != hex.EncodeToString(bssid.Addr[:]) {
		t.Errorf("BSSID = %02x, want AP BSSID", bss)
	}
}

func TestSeqRotates(t *testing.T) {
	bssid, _ := ParseMAC("00:11:22:33:44:55")
	station, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	f0 := Frame(bssid, station, 1, 0x000)
	f1 := Frame(bssid, station, 1, 0x001)
	f2 := Frame(bssid, station, 1, 0xabc)
	seq := func(f []byte) uint16 {
		return uint16(f[30]) | (uint16(f[31])>>4)<<8
	}
	if seq(f0) != 0 || seq(f1) != 1 || seq(f2) != 0xabc {
		t.Errorf("sequence not embedded: %x %x %x", seq(f0), seq(f1), seq(f2))
	}
}

func TestReasonBytes(t *testing.T) {
	bssid, _ := ParseMAC("00:11:22:33:44:55")
	station, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	f := Frame(bssid, station, ReasonDisassociatedNeedAuth, 0)
	if !(f[32] == 2 && f[33] == 0) {
		t.Errorf("reason 2 not placed at tail: % x", f[32:34])
	}
}
