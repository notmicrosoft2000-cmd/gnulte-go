package engine

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"gnulte-go/internal/pcap"
)

// fakeSource replays a fixed set of frames and then reports EOF, standing in for
// the AF_PACKET socket so the capture loop can be tested without root.
type fakeSource struct {
	frames [][]byte
	i      int
}

func (f *fakeSource) readFrame(buf []byte) (int, error) {
	if f.i >= len(f.frames) {
		return 0, io.EOF
	}
	n := copy(buf, f.frames[f.i])
	f.i++
	return n, nil
}

func (f *fakeSource) close() error { return nil }

// tickSource models a live socket with nothing to read: it times out repeatedly
// until the loop is cancelled.
type tickSource struct{}

func (tickSource) readFrame(buf []byte) (int, error) {
	time.Sleep(time.Millisecond)
	return 0, errNoFrame
}

func (tickSource) close() error { return nil }

// bufCloser adapts a bytes.Buffer to the io.WriteCloser captureLoop wants.
type bufCloser struct{ *bytes.Buffer }

func (bufCloser) Close() error { return nil }

// TestCaptureLoopWritesMatchingFrames runs the whole capture pipeline: frames in,
// filtered, and a readable libpcap file out. The unrelated frame and the ARP
// frame must not appear — only the target's traffic is recorded.
func TestCaptureLoopWritesMatchingFrames(t *testing.T) {
	wanted := ethFrame(0x0800, ipv4Body("10.0.0.9", "192.168.1.50"))
	src := &fakeSource{frames: [][]byte{
		wanted,
		ethFrame(0x0800, ipv4Body("10.0.0.9", "10.0.0.10")),
		ethFrame(0x0806, make([]byte, 28)),
	}}
	var buf bytes.Buffer
	captureLoop(context.Background(), src, bufCloser{&buf}, hostSet([]string{"192.168.1.50"}))

	r, err := pcap.NewReader(&buf)
	if err != nil {
		t.Fatalf("reopening the capture: %v", err)
	}
	if r.Header.Network != pcap.LinkTypeEthernet {
		t.Fatalf("link type = %d, want Ethernet", r.Header.Network)
	}
	p, err := r.Next()
	if err != nil {
		t.Fatalf("reading the recorded packet: %v", err)
	}
	if !bytes.Equal(p.Data, wanted) {
		t.Fatal("recorded frame does not match the target frame")
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("capture held extra packets: err = %v, want io.EOF", err)
	}
}

// TestCaptureLoopEmptyFilterKeepsEverything: with no targets the loop is the
// unfiltered tcpdump default, so non-IP frames like ARP are recorded too.
func TestCaptureLoopEmptyFilterKeepsEverything(t *testing.T) {
	arp := ethFrame(0x0806, make([]byte, 28))
	src := &fakeSource{frames: [][]byte{arp}}
	var buf bytes.Buffer
	captureLoop(context.Background(), src, bufCloser{&buf}, hostSet(nil))

	r, err := pcap.NewReader(&buf)
	if err != nil {
		t.Fatalf("reopening the capture: %v", err)
	}
	p, err := r.Next()
	if err != nil {
		t.Fatalf("reading the recorded packet: %v", err)
	}
	if !bytes.Equal(p.Data, arp) {
		t.Fatal("unfiltered capture dropped the ARP frame")
	}
}

// TestCaptureLoopStopsOnCancel checks the shutdown path: a capture with nothing
// coming in must stop when its context is cancelled, and the partial file must
// still be a valid capture (the header is written up front).
func TestCaptureLoopStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		captureLoop(ctx, tickSource{}, bufCloser{&buf}, nil)
		close(done)
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("captureLoop did not stop after its context was cancelled")
	}
	if _, err := pcap.NewReader(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("partial capture is not a valid pcap file: %v", err)
	}
}
