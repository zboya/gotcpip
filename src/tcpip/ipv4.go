package tcpip

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
)

/*
https://tools.ietf.org/html/rfc791

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 20 bytes
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

const (
	IPV4       = 0x04
	IP_TCP     = 0x06
	ICMPV4     = 0x01
	IP_HDR_LEN = 20
)

type iphdr struct {
	version     uint8
	ihl         uint8
	tos         uint8
	len         uint16
	id          uint16
	flags       uint8
	frag_offset uint16
	ttl         uint8
	proto       uint8
	csum        uint16
	saddr       net.IP
	daddr       net.IP
	options     []byte
	data        []byte
}

func ipv4_decode(skb *sk_buff) *iphdr {
	skb.head = skb.end[0:]
	ih := &iphdr{
		version:     skb.end[0] >> 4,
		ihl:         skb.end[0] & 0x0f,
		tos:         skb.end[1],
		len:         binary.BigEndian.Uint16(skb.end[2:4]),
		id:          binary.BigEndian.Uint16(skb.end[4:6]),
		flags:       uint8(skb.end[6] >> 5),
		frag_offset: binary.BigEndian.Uint16(skb.end[6:8]) & 0x1fff,
		ttl:         skb.end[8],
		proto:       skb.end[9],
		csum:        binary.BigEndian.Uint16(skb.end[10:12]),
		saddr:       make([]byte, 4),
		daddr:       make([]byte, 4),
		data:        skb.end[20:],
	}
	copy(ih.saddr, skb.end[12:16])
	copy(ih.daddr, skb.end[16:20])
	optsLen := (int(skb.end[0]&0x0f) << 2) - 20
	if optsLen > 0 {
		ih.options = make([]byte, optsLen)
		copy(ih.options, skb.end[20:20+optsLen])
	} else {
		optsLen = 0
	}
	skb.end = skb.end[20+optsLen:]
	return ih
}

func ipv4_encode(skb *sk_buff, ih *iphdr) error {
	skb.head[0] = ih.version<<4 | ih.ihl
	skb.head[1] = ih.tos
	binary.BigEndian.PutUint16(skb.head[2:4], ih.len)
	binary.BigEndian.PutUint16(skb.head[4:6], ih.id)
	binary.BigEndian.PutUint16(skb.head[6:8], ih.frag_offset|uint16(ih.flags)<<13)
	skb.head[8] = ih.ttl
	skb.head[9] = ih.proto
	skb.head[10] = 0
	skb.head[11] = 0
	copy(skb.head[12:16], ih.saddr)
	copy(skb.head[16:20], ih.daddr)
	csum := tcpipChecksum(skb.head[0:ih.ihl<<2], 0)
	binary.BigEndian.PutUint16(skb.head[10:12], csum)
	return nil
}

func ip_rcv(skb *sk_buff) error {
	ih := ipv4_decode(skb)
	log.Printf("ih: %#v", *ih)

	if ih.version != IPV4 {
		return errors.New("Datagram version was not IPv4")
	}
	if ih.ihl < 5 {
		return errors.New("IPv4 header length must be at least 5")
	}

	if ih.ttl == 0 {
		//TODO: Send ICMP error
		return errors.New("Time to live of datagram reached 0")
	}

	// TODO: Check fragmentation, possibly reassemble
	skb.head[10] = 0
	skb.head[11] = 0
	csum := tcpipChecksum(skb.head[0:ih.ihl*4], 0)
	if csum != ih.csum {
		log.Println("csum: ", csum)
		return errors.New("Invalid checksum, drop packet handling")
	}

	switch ih.proto {
	case ICMPV4:
		err := icmpv4_incoming(skb)
		if err != nil {
			return err
		}
	case IP_TCP:
		err := tcp_in(skb)
		if err != nil {
			return err
		}
	default:
		return errors.New("Unknown IP header proto")
	}

	// free_skb()
	return nil
}

func ip_output(sk *sock, skb *sk_buff) error {
	// struct rtentry *rt;
	// struct iphdr *ihdr = ip_hdr(skb);

	// rt = route_lookup(ihdr->daddr);

	// if (!rt) {
	//     // Raise error
	//     // TODO: dest_unreachable
	//     return -1;
	// }

	// skb->dev = rt->dev;
	// skb->rt = rt;

	dev := netdev_get(sk.saddr)
	if dev == nil {
		return errors.New("can't get netdev")
	}
	skb.dev = dev
	ih := new(iphdr)
	ih.version = IPV4
	ih.ihl = 0x05
	ih.tos = 0
	ih.len = uint16(len(skb.head))
	ih.flags = 0
	ih.frag_offset = 0
	ih.ttl = 64
	ih.proto = uint8(skb.protocol)
	ih.daddr = sk.daddr
	ih.saddr = dev.addr
	ih.csum = 0

	log.Printf("output ip: %#v", *ih)
	// ip_dbg("out", ihdr);
	err := ipv4_encode(skb, ih)
	if err != nil {
		return err
	}

	log.Printf("ipv4 encode: %#v", skb.head)
	// ihdr->len = htons(ihdr->len);
	// ihdr->id = htons(ihdr->id);
	// ihdr->daddr = htonl(ihdr->daddr);
	// ihdr->saddr = htonl(ihdr->saddr);
	// ihdr->csum = htons(ihdr->csum);

	// ip_send_check(ihdr);

	return dst_neigh_output(skb)
}
