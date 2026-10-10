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

// Package banners performs deeper service fingerprinting than a plaintext
// greeting read: a real TLS handshake (ServerHello version, cipher, peer name),
// an SSH identification line, and an SMB2 dialect negotiation. Everything is
// standard library only, so it builds on any platform and needs no external
// probe binary.
package banners

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// timeout bounds a single connect plus handshake or read.
const timeout = 900 * time.Millisecond

// dial opens a TCP connection with the package timeout and binds the context
// deadline (when there is one) to the socket so a cancelled scan does not
// stall on a SYN that never answers.
func dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	return c, nil
}

// TLSInfo is the part of a ServerHello worth keeping.
type TLSInfo struct {
	Version    string // e.g. "TLS 1.3"
	Cipher     string // e.g. "TLS_AES_128_GCM_SHA256"
	PeerCN     string // certificate common name, when one was presented
	ServerName string // the SNI actually sent
}

// String renders the handshake as one short banner line.
func (i TLSInfo) String() string {
	parts := []string{}
	if i.Version != "" {
		parts = append(parts, i.Version)
	}
	if i.Cipher != "" {
		parts = append(parts, i.Cipher)
	}
	if i.PeerCN != "" {
		parts = append(parts, "CN="+i.PeerCN)
	}
	if i.ServerName != "" {
		parts = append(parts, "SNI="+i.ServerName)
	}
	return strings.Join(parts, " ")
}

// TLS completes a real handshake with a TLS listener and reports the negotiated
// version and cipher. Verification is intentionally skipped: this is a probe,
// not a trust decision, and a self-signed appliance is still worth naming. When
// sni is empty and the address is a host name, that name is sent as SNI.
func TLS(ctx context.Context, addr, sni string) (TLSInfo, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := &tls.Config{InsecureSkipVerify: true}
	switch {
	case sni != "":
		cfg.ServerName = sni
	case net.ParseIP(host) == nil:
		cfg.ServerName = host
	}
	raw, err := dial(ctx, addr)
	if err != nil {
		return TLSInfo{}, err
	}
	defer raw.Close()
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return TLSInfo{}, err
	}
	st := conn.ConnectionState()
	info := TLSInfo{
		Version:    tls.VersionName(st.Version),
		Cipher:     tls.CipherSuiteName(st.CipherSuite),
		ServerName: st.ServerName,
	}
	if len(st.PeerCertificates) > 0 {
		info.PeerCN = st.PeerCertificates[0].Subject.CommonName
	}
	return info, nil
}

// SSH reads the identification line an SSH daemon sends before key exchange,
// e.g. "SSH-2.0-OpenSSH_9.3p1". A reply that does not start with "SSH-" is
// rejected so an unrelated listener is not mislabelled.
func SSH(ctx context.Context, addr string) (string, error) {
	c, err := dial(ctx, addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	line, err := bufio.NewReader(io.LimitReader(c, 512)).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "SSH-") {
		return "", fmt.Errorf("not an SSH identification line: %q", line)
	}
	return line, nil
}

// SMB probes a Windows file-sharing listener with an SMB2 NEGOTIATE and names
// the dialect the server selected ("SMB 3.1.1", "SMB 2.1", …). A server that
// answers with the legacy SMB1 header is reported as "SMB 1".
func SMB(ctx context.Context, addr string) (string, error) {
	c, err := dial(ctx, addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Write(negotiateRequest()); err != nil {
		return "", err
	}
	var nb [4]byte
	if _, err := io.ReadFull(c, nb[:]); err != nil {
		return "", err
	}
	if nb[0] != 0 {
		return "", fmt.Errorf("bad NetBIOS session header 0x%02x", nb[0])
	}
	n := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if n < 4 || n > 1<<16 {
		return "", fmt.Errorf("implausible SMB frame length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return "", err
	}
	if len(body) >= 4 && body[0] == 0xFF && string(body[1:4]) == "SMB" {
		return "SMB 1", nil
	}
	if len(body) < 70 || body[0] != 0xFE || string(body[1:4]) != "SMB" {
		return "", fmt.Errorf("not an SMB2 negotiate reply")
	}
	// SMB2 header is 64 bytes; the negotiate body starts there with
	// StructureSize(2) SecurityMode(2) DialectRevision(2).
	rev := binary.LittleEndian.Uint16(body[68:70])
	return smbDialect(rev), nil
}

// smbDialects lists the revisions we offer, newest first, excluding 3.1.1
// whose negotiate context we do not implement. A server picks from this list.
var smbDialects = []uint16{0x0302, 0x0300, 0x0210, 0x0202}

// negotiateRequest builds a NetBIOS-framed SMB2 NEGOTIATE request.
func negotiateRequest() []byte {
	h := make([]byte, 64)
	h[0], h[1], h[2], h[3] = 0xFE, 'S', 'M', 'B' // SMB2 protocol id
	binary.LittleEndian.PutUint16(h[4:], 64)     // StructureSize
	binary.LittleEndian.PutUint16(h[6:], 1)      // CreditCharge
	binary.LittleEndian.PutUint16(h[14:], 1)     // CreditRequest
	// Command (h[12:]) stays 0 = NEGOTIATE; MessageId 0; flags 0.

	body := make([]byte, 36+2*len(smbDialects))
	binary.LittleEndian.PutUint16(body[0:], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:], uint16(len(smbDialects)))
	for i, d := range smbDialects {
		binary.LittleEndian.PutUint16(body[36+2*i:], d)
	}

	smb := append(h, body...)
	out := make([]byte, 4, 4+len(smb))
	l := len(smb)
	out[1], out[2], out[3] = byte(l>>16), byte(l>>8), byte(l)
	return append(out, smb...)
}

func smbDialect(rev uint16) string {
	switch rev {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB 1"
	default:
		return fmt.Sprintf("SMB dialect 0x%04X", rev)
	}
}
