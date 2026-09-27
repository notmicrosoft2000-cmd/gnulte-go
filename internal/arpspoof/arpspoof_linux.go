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

//go:build linux

package arpspoof

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// Spoofer is one AF_PACKET socket bound to an interface's ARP traffic. It can
// send directed unicast ARP replies and read inbound ARP requests (broadcast,
// no promiscuous mode needed) so the caller answers only when actually asked.
type Spoofer struct {
	fd    int
	idx   int
	iface string

	ourMAC net.HardwareAddr
	ourIP  net.IP
}

// Open binds a raw AF_PACKET socket to the interface and resolves the local
// MAC/IPv4 it will claim frames come from. Needs root/CAP_NET_RAW.
func Open(iface string) (*Spoofer, error) {
	nif, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	if len(nif.HardwareAddr) != 6 {
		return nil, fmt.Errorf("interface %s has no Ethernet MAC", iface)
	}
	ip := ifaceIPv4(nif)
	if ip == nil {
		return nil, fmt.Errorf("interface %s has no IPv4 address", iface)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPArp)))
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPArp), Ifindex: nif.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	_ = syscall.SetNonblock(fd, true) // read loop polls; never blocks a Stop()
	return &Spoofer{fd: fd, idx: nif.Index, iface: iface, ourMAC: nif.HardwareAddr, ourIP: ip}, nil
}

// ifaceIPv4 returns the interface's first global unicast IPv4 address.
func ifaceIPv4(nif *net.Interface) net.IP {
	addrs, err := nif.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
			return ip4
		}
	}
	return nil
}

// SendReply places one directed unicast ARP reply on the wire telling toMAC
// (at toIP) that claimedIP now resolves to us.
func (sp *Spoofer) SendReply(toMAC net.HardwareAddr, toIP, claimedIP net.IP) error {
	if len(toMAC) != 6 {
		return errors.New("arp spoof: destination MAC must be 6 bytes")
	}
	frame := BuildARPReply(sp.ourMAC, claimedIP, toIP, toMAC)
	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPArp),
		Ifindex:  sp.idx,
		Halen:    6,
	}
	copy(sa.Addr[:], toMAC)
	return syscall.Sendto(sp.fd, frame, 0, sa)
}

// ReadRequest drains one pending ARP request frame, or reports ok=false when
// the socket has nothing waiting (EAGAIN). A request whose sender is us is
// skipped by the caller via IsLocal.
func (sp *Spoofer) ReadRequest() (fromMAC net.HardwareAddr, fromIP, askedIP net.IP, ok bool, err error) {
	buf := make([]byte, 2048)
	n, _, err := syscall.Recvfrom(sp.fd, buf, 0)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return nil, nil, nil, false, nil
		}
		return nil, nil, nil, false, err
	}
	fromMAC, fromIP, asked, ok := ParseARPRequest(buf[:n])
	return fromMAC, fromIP, asked, ok, nil
}

// Close releases the socket.
func (sp *Spoofer) Close() error {
	if sp.fd >= 0 {
		fd := sp.fd
		sp.fd = -1
		return syscall.Close(fd)
	}
	return nil
}

// htons converts a 16-bit value to network byte order (a byte swap on the
// little-endian hosts AF_PACKET is normally used on).
func htons(v uint16) uint16 { return v<<8 | v>>8 }
