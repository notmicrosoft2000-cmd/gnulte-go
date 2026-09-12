// GNULTE-GO — network testing toolkit.
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

// Package netutil resolves the current network configuration: default
// interface, gateway, this machine's IP, and CIDR maths. It reads the kernel
// route table via /proc rather than shelling to `ip`, so a build has no
// runtime deps for configuration discovery.
package netutil

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// Config describes the auto-detected network we are operating on.
type Config struct {
	Interface  string
	Gateway    string
	SelfIP     string
	Netmask    string
	GatewayMAC string
}

// DefaultRoute reads /proc/net/route to find the default gateway device and
// the system IP/netmask from net.Interfaces.
func DefaultRoute() (Config, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		dest, gw := fields[1], fields[2]
		ifaceName := fields[0]
		if dest != "00000000" {
			continue // not the default route
		}
		gwIP := hexToIP(gw)
		if gwIP == nil {
			continue
		}
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			continue
		}
		self, netmask, err := ifaceAddr(iface)
		if err != nil {
			continue
		}
		return Config{
			Interface: ifaceName,
			Gateway:   gwIP.String(),
			SelfIP:    self,
			Netmask:   netmask,
		}, nil
	}
	return Config{}, fmt.Errorf("could not determine default route")
}

func ifaceAddr(iface *net.Interface) (string, string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return "", "", err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String(), net.IP(ipnet.Mask).String(), nil
	}
	return "", "", fmt.Errorf("no IPv4 address on %s", iface.Name)
}

// hexToIP converts a little-endian hex route field to an IPv4 address.
func hexToIP(h string) net.IP {
	if len(h) != 8 {
		return nil
	}
	var v [4]byte
	if _, err := fmt.Sscanf(h, "%02x%02x%02x%02x", &v[0], &v[1], &v[2], &v[3]); err != nil {
		return nil
	}
	// Read as native 32-bit then convert to big-endian IPv4.
	u := binary.LittleEndian.Uint32(v[:])
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, u)
	return ip
}

// GatewayMAC resolves the gateway's MAC from the neighbor table (may be empty).
func GatewayMAC(gw string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 6 && fields[0] == gw {
			return fields[3]
		}
	}
	return ""
}

// ApplyDefaults fills any empty fields from a provided CIDR (as net.IPNet).
func ApplyDefaults(c Config, ipn *net.IPNet) Config {
	if c.Interface == "" && ipn != nil {
		if ip4 := ipn.IP.To4(); ip4 != nil {
			c.SelfIP = ip4.String()
		}
		ones, _ := ipn.Mask.Size()
		if ones <= 32 {
			c.Netmask = net.IP(ipn.Mask).String()
		}
	}
	return c
}

// HostsInCIDR expands an IPv4 CIDR into every address it covers.
func HostsInCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 scanning is supported (got %q)", cidr)
	}
	var list []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		list = append(list, cur.String())
	}
	return list, nil
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
