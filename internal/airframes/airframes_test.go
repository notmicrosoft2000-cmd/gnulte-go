// GNULTE — network testing toolkit. Licensed under the GNU GPL version 3.

package airframes

import (
	"bytes"
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

func TestDeauthFrameGolden(t *testing.T) {
	bssid, _ := ParseMAC("00:0c:41:63:45:6a")
	station, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	got := DeauthFrame(bssid, station, ReasonLeavingBSS, 0)
	if len(got) != DeauthFrameSize {
		t.Fatalf("DeauthFrame length = %d, want %d", len(got), DeauthFrameSize)
	}
	want := "0000080000000000" + // radiotap
		"c000" + "0000" + // frame control (deauth) + duration
		"aabbccddeeff" + // destination = victim
		"000c4163456a" + // source = AP BSSID
		"000c4163456a" + // BSSID = AP
		"0000" + // sequence
		"0700" // reason 7
	if hex.EncodeToString(got) != want {
		t.Errorf("DeauthFrame = %s\n want           %s", hex.EncodeToString(got), want)
	}
}

func TestDeauthSourceIsBSSID(t *testing.T) {
	bssid, _ := ParseMAC("00:0c:41:63:45:6a")
	station, _ := ParseMAC("10:20:30:40:50:60")
	f := DeauthFrame(bssid, station, ReasonUnspecified, 0)
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

func seqField(f []byte) uint16 {
	return uint16(f[30]) | (uint16(f[31])>>4)<<8
}

func TestSeqRotates(t *testing.T) {
	bssid, _ := ParseMAC("00:11:22:33:44:55")
	station, _ := ParseMAC("aa:bb:cc:dd:ee:ff")
	f0 := DeauthFrame(bssid, station, 1, 0x000)
	f1 := DeauthFrame(bssid, station, 1, 0x001)
	f2 := DeauthFrame(bssid, station, 1, 0xabc)
	if seqField(f0) != 0 || seqField(f1) != 1 || seqField(f2) != 0xabc {
		t.Errorf("sequence not embedded: %x %x %x", seqField(f0), seqField(f1), seqField(f2))
	}
}

func TestAuthFrameStructure(t *testing.T) {
	bssid, _ := ParseMAC("00:0c:41:63:45:6a")
	client, _ := ParseMAC("de:ad:be:ef:00:01")
	f := AuthFrame(bssid, client, 0, 1, 0, 7)
	if len(f) != AuthFrameSize {
		t.Fatalf("AuthFrame length = %d, want %d", len(f), AuthFrameSize)
	}
	// FC should be 0xb0 (management + auth subtype).
	if f[8] != 0xb0 {
		t.Errorf("frame control = %02x, want b0", f[8])
	}
	// DA = BSSID (to the AP), SA = client.
	if hex.EncodeToString(f[12:18]) != "000c4163456a" {
		t.Errorf("DA = %02x, want AP", f[12:18])
	}
	if hex.EncodeToString(f[18:24]) != "deadbeef0001" {
		t.Errorf("SA = %02x, want client", f[18:24])
	}
	// Body: algorithm=0 (open), seq=1, status=0.
	body := f[32:]
	if hex.EncodeToString(body) != "000001000000" {
		t.Errorf("auth body = %s, want open-system seq=1 status=0", hex.EncodeToString(body))
	}
}

func TestBeaconFrameStructure(t *testing.T) {
	bssid := FakeBSSID()
	f := BeaconFrame(bssid, "GNULTE-TEST", 6, 3)
	if f[8] != 0x80 {
		t.Errorf("frame control = %02x, want 80 (beacon)", f[8])
	}
	if bssid.IsBroadcast() {
		t.Fatal("bssid not usable")
	}
	if hex.EncodeToString(f[12:18]) != "ffffffffffff" {
		t.Errorf("DA = %02x, want broadcast", f[12:18])
	}
	if hex.EncodeToString(f[18:24]) != hex.EncodeToString(bssid.Addr[:]) {
		t.Errorf("SA = %02x, want fake BSSID", f[18:24])
	}
	// SSID element must carry the name.
	want := "GNULTE-TEST"
	if !bytes.Contains(f, []byte(want)) {
		t.Errorf("beacon does not carry SSID %q", want)
	}
	// Channel element present (ID 3, len 1, channel 6).
	if !bytes.Contains(f, []byte{0x03, 0x01, 0x06}) {
		t.Errorf("beacon missing channel 6 (%s)", hex.EncodeToString(f))
	}
	if seqField(f) != 3 {
		t.Errorf("beacon seq = %d, want 3", seqField(f))
	}
}

func TestFakeMACsAreSafe(t *testing.T) {
	m := FakeStation()
	if m.Addr[0]&0x01 != 0 || m.Addr[0]&0x02 == 0 {
		t.Errorf("FakeStation not locally-administered unicast: %s", m)
	}
	b := FakeBSSID()
	if b.Addr[0]&0x02 == 0 {
		t.Errorf("FakeBSSID not locally administered: %s", b)
	}
}

func TestParseChannels(t *testing.T) {
	ch, err := ParseChannels("1, 6, 11")
	if err != nil || len(ch) != 3 || ch[0] != 1 || ch[2] != 11 {
		t.Errorf("ParseChannels(1,6,11) = %v, %v want [1 6 11]", ch, err)
	}
	// Duplicates collapse, order kept.
	ch, err = ParseChannels("6,6,1")
	if err != nil || len(ch) != 2 || ch[0] != 6 || ch[1] != 1 {
		t.Errorf("dedupe = %v, %v want [6 1]", ch, err)
	}
	if _, err := ParseChannels(""); err == nil {
		t.Error("empty list should fail")
	}
	if _, err := ParseChannels("1,99,200"); err == nil {
		t.Error("out-of-range channel should fail")
	}
	if _, err := ParseChannels("1,x"); err == nil {
		t.Error("non-numeric channel should fail")
	}
}

func TestReasonCodesRotate(t *testing.T) {
	rc := ReasonCodes()
	if len(rc) < 3 {
		t.Fatalf("ReasonCodes() = %v, want a rotating set", rc)
	}
	// The classic "legitimate disconnect" reason must be in the mix.
	found := false
	for _, r := range rc {
		if r == ReasonLeavingBSS {
			found = true
		}
	}
	if !found {
		t.Error("ReasonCodes missing the canonical LeaveBSS reason")
	}
}
