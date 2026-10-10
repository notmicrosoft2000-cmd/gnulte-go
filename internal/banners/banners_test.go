package banners

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSSH answers every connection with an identification line.
func fakeSSH(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, banner)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSSHGrab(t *testing.T) {
	addr := fakeSSH(t, "SSH-2.0-OpenSSH_9.3p1 Ubuntu\r\n")
	got, err := SSH(context.Background(), addr)
	if err != nil {
		t.Fatalf("SSH: %v", err)
	}
	if got != "SSH-2.0-OpenSSH_9.3p1 Ubuntu" {
		t.Errorf("SSH banner = %q", got)
	}
}

func TestSSHRejectsNonSSH(t *testing.T) {
	addr := fakeSSH(t, "220 FTP server ready\r\n")
	if _, err := SSH(context.Background(), addr); err == nil {
		t.Errorf("a non-SSH greeting must be rejected")
	}
}

// selfSigned returns a leaf certificate for fake.local.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"fake.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return cert
}

func TestTLSHandshake(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()

	info, err := TLS(context.Background(), ln.Addr().String(), "")
	if err != nil {
		t.Fatalf("TLS: %v", err)
	}
	if info.Version != "TLS 1.3" {
		t.Errorf("version = %q, want TLS 1.3", info.Version)
	}
	if info.Cipher == "" {
		t.Errorf("cipher is empty")
	}
	if info.PeerCN != "fake.local" {
		t.Errorf("peer CN = %q, want fake.local", info.PeerCN)
	}
	if s := info.String(); !strings.Contains(s, "TLS 1.3") || !strings.Contains(s, "CN=fake.local") {
		t.Errorf("String() = %q", s)
	}
}

// fakeSMB accepts one connection, reads the request, and answers with an SMB2
// negotiate reply (or an SMB1 header when rev == 0).
func fakeSMB(t *testing.T, rev uint16, smb1 bool) (string, *[]byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make([]byte, 0, 256)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		got = append(got, buf[:n]...)
		var body []byte
		if smb1 {
			body = make([]byte, 40)
			body[0], body[1], body[2], body[3] = 0xFF, 'S', 'M', 'B'
		} else {
			body = make([]byte, 72)
			body[0], body[1], body[2], body[3] = 0xFE, 'S', 'M', 'B'
			binary.LittleEndian.PutUint16(body[4:], 65) // StructureSize
			binary.LittleEndian.PutUint16(body[68:], rev)
		}
		frame := make([]byte, 4)
		l := len(body)
		frame[1], frame[2], frame[3] = byte(l>>16), byte(l>>8), byte(l)
		_, _ = c.Write(append(frame, body...))
	}()
	time.Sleep(20 * time.Millisecond) // let Accept land before the probe connects
	return ln.Addr().String(), &got
}

func TestSMBNegotiate(t *testing.T) {
	addr, got := fakeSMB(t, 0x0311, false)
	name, err := SMB(context.Background(), addr)
	if err != nil {
		t.Fatalf("SMB: %v", err)
	}
	if name != "SMB 3.1.1" {
		t.Errorf("dialect = %q, want SMB 3.1.1", name)
	}
	// The request must be a NetBIOS-framed SMB2 negotiate offering our list.
	if len(*got) < 8 || (*got)[0] != 0 || (*got)[4] != 0xFE || string((*got)[5:8]) != "SMB" {
		end := len(*got)
		if end > 8 {
			end = 8
		}
		t.Fatalf("request is not a framed SMB2 packet: % x", (*got)[:end])
	}
	// The offered dialect list must carry at least our modern entries:
	// NBSS(4) + SMB2 header(64) + StructureSize(2) then DialectCount(2).
	if len(*got) < 72 || binary.LittleEndian.Uint16((*got)[70:72]) != uint16(len(smbDialects)) {
		t.Errorf("negotiate dialect list malformed (len=%d)", len(*got))
	}
}

func TestSMBDialectTable(t *testing.T) {
	for rev, want := range map[uint16]string{
		0x0202: "SMB 2.0.2",
		0x0210: "SMB 2.1",
		0x0300: "SMB 3.0",
		0x0302: "SMB 3.0.2",
		0x0311: "SMB 3.1.1",
		0x9999: "SMB dialect 0x9999",
	} {
		if got := smbDialect(rev); got != want {
			t.Errorf("smbDialect(0x%04X) = %q, want %q", rev, got, want)
		}
	}
}

func TestSMBSMB1(t *testing.T) {
	addr, _ := fakeSMB(t, 0, true)
	name, err := SMB(context.Background(), addr)
	if err != nil {
		t.Fatalf("SMB: %v", err)
	}
	if name != "SMB 1" {
		t.Errorf("dialect = %q, want SMB 1", name)
	}
}
