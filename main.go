package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var (
	firstDNS             = net.ParseIP("2001:4860:4860::8888").To16()
	secondDNS            = net.ParseIP("2001:4860:4860::8844").To16()
	ip6AllNodesMulticast = netip.IPv6LinkLocalAllNodes()

	lifetime    uint32 = 86401
	advInterval        = 60 * time.Second
)

func main() {
	log.SetFlags(0)
	flagIface := flag.String("iface", "eth0", "interface to find ip")
	flagPrefix := flag.String("prefix", "", "ipv6 prefix to use")
	flagLoop := flag.Bool("loop", false, "send advs every 60 seconds")
	flag.Parse()

	if *flagPrefix == "" {
		log.Printf("must specify prefix")
		os.Exit(1)
	}

	pref, err := netip.ParsePrefix(*flagPrefix)
	if err != nil {
		log.Fatalf("invalid prefix: %s", err)
	}
	netDevice := *flagIface

	macAddr, addr, err := currentIPS(netDevice)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("to add routing:\n\n")
	fmt.Printf("ip route add %s/64 dev %s\n\n", pref.Addr(), netDevice)

	wm := icmp.Message{
		Type: ipv6.ICMPTypeRouterAdvertisement, Code: 0,
		Body: &advPacket{
			prefix:   pref.Addr().AsSlice(),
			macBytes: macAddr,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	liAddr := addr.String() + "%" + netDevice
	log.Printf("start listening on %s", liAddr)
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", liAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	dstAddr := &net.IPAddr{
		IP:   net.ParseIP(ip6AllNodesMulticast.String()),
		Zone: *flagIface,
	}

	// this is important as otherwise these packets are discarded
	if err := c.IPv6PacketConn().SetMulticastHopLimit(255); err != nil {
		log.Fatalf("failed to set hoplimit: %s", err)
	}
	hoplimit, err := c.IPv6PacketConn().MulticastHopLimit()
	if err != nil {
		log.Fatalf("failed get hoplimit: %s", err)
	}

	for {
		log.Printf("sending packet to %s (hoplimit=%d)...", dstAddr, hoplimit)
		if _, err := c.WriteTo(wb, dstAddr); err != nil {
			log.Fatal(err)
		}

		if !*flagLoop {
			break
		}
		log.Printf("packet sent! (sleep %s)", advInterval)
		time.Sleep(advInterval)
	}
}

func currentIPS(iface string) (hwAddr net.HardwareAddr, found netip.Addr, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("error getting interfaces list: %s", err)
		return
	}
	for _, i := range ifaces {
		var addrs []net.Addr

		if i.Name != iface {
			continue
		}

		log.Printf("if: %d", i.Index)
		addrs, err = i.Addrs()
		if err != nil {
			log.Printf("error getting address list: %s", err)
			return
		}
		hwAddr = i.HardwareAddr
		for _, a := range addrs {
			log.Printf("parse: %s", a)
			ap, err := netip.ParsePrefix(a.String())
			if err != nil {
				log.Printf("parsing %q prefix failed: %s", a, err)
				continue
			}
			aa := ap.Addr()
			if !aa.Is6() {
				continue
			}

			if !aa.IsLinkLocalUnicast() {
				continue
			}

			log.Printf("hwaddr=%s iface=%s addr=%s", hwAddr, i.Name, ap.Addr())
			found = aa
		}
	}

	if !found.Is6() {
		err = errors.New("no v6 address found")
	}

	return
}

const advSize = 100

type advPacket struct {
	prefix net.IP

	macBytes []byte
}

func (ap *advPacket) Marshal(proto int) ([]byte, error) {
	// TODO: Fix buffer filling instead of using static offsets
	ret := make([]byte, advSize)

	// RFC 4861 4.2 first 16 bytes
	ret[0] = 64                                // hop limit
	ret[1] = 0x00                              // flags
	binary.BigEndian.PutUint16(ret[2:4], 3600) // router lifetime seconds
	binary.BigEndian.PutUint32(ret[4:8], 0)    // reachable in ms
	binary.BigEndian.PutUint32(ret[8:12], 0)   // retrans timer in ms

	// prefix option
	//    0                   1                   2                   3
	//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |                         Valid Lifetime                        |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |                       Preferred Lifetime                      |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |                           Reserved2                           |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |                                                               |
	//   +                                                               +
	//   |                                                               |
	//   +                            Prefix                             +
	//   |                                                               |
	//   +                                                               +
	//   |                                                               |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	ret[12] = 3
	ret[13] = 4                                      // length 32 bytes
	ret[14] = 64                                     // 64 bit prefix len
	ret[15] = 0x80 | 0x40                            // flags onlink + autonomous config
	binary.BigEndian.PutUint32(ret[16:20], lifetime) // valid lifetime
	binary.BigEndian.PutUint32(ret[20:24], lifetime) // preferred lifetime
	binary.BigEndian.PutUint32(ret[24:28], 0)        // reserved
	for i := range 16 {
		ret[28+i] = ap.prefix[i]
	}

	// mtu option
	//    0                   1                   2                   3
	//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |     Type      |    Length     |           Reserved            |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |                              MTU                              |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	ret[44] = 5
	ret[45] = 1                                  // length 8 bytes
	ret[46] = 0                                  // reserved
	ret[47] = 0                                  // reserved
	binary.BigEndian.PutUint32(ret[48:52], 1480) // mtu (1500 - ipv4 header 20)

	// source link option, mac address
	//   0                   1                   2                   3
	//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |     Type      |    Length     |    Link-Layer Address ...
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	ret[52] = 1
	ret[53] = 1
	for i := range 6 {
		ret[54+i] = ap.macBytes[i]
	}

	// dns option RFC 8106
	//   0                   1                   2                   3
	//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |     Type      |     Length    |           Reserved            |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                           Lifetime                            |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                                                               |
	//  :            Addresses of IPv6 Recursive DNS Servers            :
	//  |                                                               |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	ret[60] = 25
	ret[61] = 5                                      // length 40 bytes (two dns servers)
	ret[62] = 0                                      // reserved
	ret[63] = 0                                      // reserved
	binary.BigEndian.PutUint32(ret[64:68], lifetime) // lifetime
	for i := range 16 {
		ret[68+i] = firstDNS[i]
	}
	for i := range 16 {
		ret[84+i] = secondDNS[i]
	}

	return ret, nil
}

func (ap *advPacket) Len(proto int) int {
	return advSize
}
