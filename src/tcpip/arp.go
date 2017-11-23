package tcpip

import (
	"encoding/binary"
	"log"
)

const (
	ARP_ETHERNET = 0x0001
	ARP_IPV4     = 0x0800
	ARP_REQUEST  = 0x0001
	ARP_REPLY    = 0x0002
)

// https://tools.ietf.org/html/rfc826
/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      hwtype(2 bytes)        |       protype(2 bytes)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|hwsize(1bytes) |psize(1bytes)|        opcode(2 bytes)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 8bytes
|       smac(6 bytes)         |				sip(4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       dmac(6 bytes)         |				dip(4 bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 28 bytes
*/

// 8 bytes
type arp_hdr struct {
	hwtype  uint16
	protype uint16
	hwsize  uint8
	prosize uint8
	opcode  uint16
	data    []byte
}

// 20 bytes
type arp_ipv4 struct {
	smac []byte
	sip  []byte
	dmac []byte
	dip  []byte
}

func arp_hdr_decode(skb *sk_buff) *arp_hdr {
	hdr := &arp_hdr{
		hwtype:  binary.BigEndian.Uint16(skb.end[0:2]),
		protype: binary.BigEndian.Uint16(skb.end[2:4]),
		hwsize:  skb.end[4],
		prosize: skb.end[5],
		opcode:  binary.BigEndian.Uint16(skb.end[6:8]),
		data:    skb.end[8:],
	}
	return hdr
}

func (a *arp_hdr) arp_hdr_encode(skb *sk_buff) {
	binary.BigEndian.PutUint16(skb.end[0:2], a.hwtype)
	binary.BigEndian.PutUint16(skb.end[2:4], a.protype)
	skb.end[4] = a.hwsize
	skb.end[5] = a.prosize
	binary.BigEndian.PutUint16(skb.end[6:8], a.opcode)
	return
}

func (h *arp_hdr) arp_ipv4_decode() *arp_ipv4 {
	return &arp_ipv4{
		smac: h.data[0:6],
		sip:  h.data[6:10],
		dmac: h.data[10:16],
		dip:  h.data[16:20],
	}
}

func (h *arp_hdr) arp_ipv4_encode(dev *netdev) {
	copy(h.data[10:16], h.data[0:6])
	copy(h.data[16:20], h.data[6:10])
	copy(h.data[0:6], dev.hwaddr[:])
	copy(h.data[6:10], dev.addr)
}

func arp_rcv(skb *sk_buff) error {
	arphdr := arp_hdr_decode(skb)

	if arphdr.hwtype != ARP_ETHERNET {
		log.Printf("ARP: Unsupported HW type\n")
		return nil
	}

	if arphdr.protype != ARP_IPV4 {
		log.Printf("ARP: Unsupported protocol\n")
		return nil
	}

	arpdata := arphdr.arp_ipv4_decode()

	// if (!(netdev = netdev_get(arpdata->dip))) {
	//     printf("ARP was not for us\n");
	//     return nil;
	// }

	dev := netdev_get(arpdata.dip)
	if dev == nil {
		log.Printf("ARP was not for us\n")
		return nil
	}

	log.Printf("get dev: %+v", *dev)

	switch arphdr.opcode {
	case ARP_REQUEST:
		err := arp_reply(skb, dev)
		return err
	default:
		log.Printf("ARP: Opcode not supported\n")
		return nil
	}
}

func arp_reply(skb *sk_buff, dev *netdev) error {
	arphdr := arp_hdr_decode(skb)
	arpdata := arphdr.arp_ipv4_decode()
	arphdr.arp_ipv4_encode(dev)
	arphdr.opcode = ARP_REPLY
	arphdr.arp_hdr_encode(skb)
	log.Printf("arp reply\n")
	skb.dev = dev
	return netdev_transmit(skb, arpdata.dmac, ETH_P_ARP)
}
