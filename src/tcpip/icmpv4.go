package tcpip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
)

/*
https://tools.ietf.org/html/rfc792

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 4 bytes
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

const (
	ICMP_V4_REPLY           = 0x00
	ICMP_V4_DST_UNREACHABLE = 0x03
	ICMP_V4_SRC_QUENCH      = 0x04
	ICMP_V4_REDIRECT        = 0x05
	ICMP_V4_ECHO            = 0x08
	ICMP_V4_ROUTER_ADV      = 0x09
	ICMP_V4_ROUTER_SOL      = 0x0a
	ICMP_V4_TIMEOUT         = 0x0b
	ICMP_V4_MALFORMED       = 0x0c
)

type icmpv4 struct {
	_type uint8
	code  uint8
	csum  uint16
	data  []byte
}

func icmpv4_decode(skb *sk_buff) *icmpv4 {
	return &icmpv4{
		_type: skb.end[0],
		code:  skb.end[1],
		csum:  binary.BigEndian.Uint16(skb.end[2:4]),
		data:  skb.end[4:],
	}
}

func icmpv4_encode(skb *sk_buff, icmp *icmpv4) {
	skb.end[0] = icmp._type
	skb.end[1] = icmp.code
	skb.end[2] = 0
	skb.end[3] = 0
	csum := tcpipChecksum(skb.end, 0)
	binary.BigEndian.PutUint16(skb.end[2:4], csum)
}

func icmpv4_incoming(skb *sk_buff) error {
	icmp := icmpv4_decode(skb)
	log.Printf("icmp: %#v", *icmp)

	//TODO: Check csum
	switch icmp._type {
	case ICMP_V4_ECHO:
		err := icmpv4_reply(skb)
		if err != nil {
			return err
		}
	case ICMP_V4_DST_UNREACHABLE:
		return fmt.Errorf("ICMPv4 received 'dst unreachable' code %d", icmp.code)
	default:
		return errors.New("ICMPv4 did not match supported types")
	}

	return nil
}

func icmpv4_reply(skb *sk_buff) error {
	// struct iphdr *iphdr = ip_hdr(skb);
	// struct icmp_v4 *icmp;
	// struct sock sk;
	// memset(&sk, 0, sizeof(struct sock));

	// uint16_t icmp_len = iphdr->len - (iphdr->ihl * 4);

	// skb_reserve(skb, ETH_HDR_LEN + IP_HDR_LEN + icmp_len);
	// skb_push(skb, icmp_len);

	// icmp = (struct icmp_v4 *)skb->data;

	// icmp->type = ICMP_V4_REPLY;
	// icmp->csum = 0;
	// icmp->csum = checksum(icmp, icmp_len, 0);

	// skb->protocol = ICMPV4;
	// sk.daddr = iphdr->saddr;

	// ip_output(&sk, skb);
	// free_skb(skb);

	icmp := icmpv4_decode(skb)
	icmp._type = ICMP_V4_REPLY
	icmp.csum = 0
	icmpv4_encode(skb, icmp)

	log.Printf("icmp encode: %#v", skb.end)
	// skb_reserve
	// end:=len(skb.data)
	// icmpLen:=len(skb.head)
	// head:=end-icmpLen
	// skb.head=skb.data()
	skb.protocol = ICMPV4
	skb.end = skb.head
	ih := ipv4_decode(skb)
	sk := &sock{
		saddr: ih.daddr,
		daddr: ih.saddr,
	}
	log.Printf("get ip head: %#v", *ih)
	err := ip_output(sk, skb)
	return err
}
