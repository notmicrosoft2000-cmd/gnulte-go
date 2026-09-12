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

// Package sound emits short tones for ping/scan events. On Linux it writes a
// tiny 16-bit mono WAV and plays it with a detected player (aplay, paplay, or
// sox's play). If no player exists it falls back to the terminal bell.
package sound

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"os/exec"
	"sync"
	"time"
)

var (
	playerOnce sync.Once
	player     string
	playerOK   bool
)

// playerPath detects an audio player once.
func playerPath() (string, bool) {
	playerOnce.Do(func() {
		for _, name := range []string{"aplay", "paplay", "play"} {
			if p, err := exec.LookPath(name); err == nil {
				player, playerOK = p, true
				return
			}
		}
	})
	return player, playerOK
}

// Beep plays a sine tone (frequency Hz, duration seconds), non-blocking.
func Beep(freq float64, dur time.Duration) {
	p, ok := playerPath()
	if !ok || freq <= 0 || dur <= 0 {
		// Fallback: terminal bell, rate-limited by the caller's cadence.
		os.Stdout.WriteString("\a")
		return
	}
	path := writeWAV(freq, dur)
	cmd := exec.Command(p, "-q", path)
	if p != "" && !isAplay(p) {
		cmd = exec.Command(p, path)
	}
	if err := cmd.Start(); err != nil {
		os.Remove(path)
		os.Stdout.WriteString("\a")
		return
	}
	go func() {
		_ = cmd.Wait()
		os.Remove(path)
	}()
}

func isAplay(p string) bool {
	return len(p) >= 5 && p[len(p)-5:] == "aplay"
}

// PingResult picks a tone from the round-trip time: higher pitch for faster
// replies (clamped to 300-1200 Hz), and a low 196 Hz buzz when a ping is lost.
func PingResult(rttMs int, ok bool) {
	if !ok {
		Beep(196, 300*time.Millisecond)
		return
	}
	f := 1200.0 - float64(rttMs)/2.0
	if f < 300 {
		f = 300
	}
	if f > 1200 {
		f = 1200
	}
	Beep(f, 90*time.Millisecond)
}

// Found blips when a device is discovered during a scan.
func Found() { Beep(880, 70*time.Millisecond) }

// Empty emits the "nothing found" buzz.
func Empty() { Beep(196, 350*time.Millisecond) }

func writeWAV(freq float64, dur time.Duration) string {
	const rate = 44100
	n := int(float64(rate) * dur.Seconds())
	if n < 1 {
		n = 1
	}
	var buf bytes.Buffer
	dataSize := n * 2

	// RIFF header
	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(36+dataSize))
	buf.WriteString("WAVE")
	buf.WriteString("fmt ")
	binary.Write(&buf, binary.LittleEndian, uint32(16))     // subchunk size
	binary.Write(&buf, binary.LittleEndian, uint16(1))      // PCM
	binary.Write(&buf, binary.LittleEndian, uint16(1))      // mono
	binary.Write(&buf, binary.LittleEndian, uint32(rate))   // sample rate
	binary.Write(&buf, binary.LittleEndian, uint32(rate*2)) // byte rate
	binary.Write(&buf, binary.LittleEndian, uint16(2))      // block align
	binary.Write(&buf, binary.LittleEndian, uint16(16))     // bits
	buf.WriteString("data")
	binary.Write(&buf, binary.LittleEndian, uint32(dataSize))

	for i := 0; i < n; i++ {
		// Fade the last 10% and first 2% to avoid clicks.
		env := 1.0
		frac := float64(i) / float64(n)
		const fade = 0.1
		if frac < 0.02 {
			env = frac / 0.02
		} else if frac > 1.0-fade {
			env = (1.0 - frac) / fade
		}
		val := math.Sin(2*math.Pi*freq*float64(i)/rate) * env * 0.35
		binary.Write(&buf, binary.LittleEndian, int16(val*math.MaxInt16))
	}

	f, err := os.CreateTemp("", "gnulte-go-beep-*.wav")
	if err != nil {
		return ""
	}
	name := f.Name()
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		os.Remove(name)
		return ""
	}
	f.Close()
	return name
}
