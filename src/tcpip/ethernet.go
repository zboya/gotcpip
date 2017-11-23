package tcpip

import (
	"encoding/binary"
)

const (
	ETH_HDR_LEN = 14
)

/*
https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
 dmac	smac 	 type	 数据	 		    FCS
 6bytes	6bytes	2bytes	 46～1500bytes	 4bytes
*/

type eth_hdr struct {
	dmac      []byte
	smac      []byte
	ethertype uint16
	payload   []byte
}

func eth_hdr_decode(skb *sk_buff) *eth_hdr {
	skb.head = skb.end[0:]
	hdr := &eth_hdr{
		dmac:      make([]byte, 6),
		smac:      make([]byte, 6),
		ethertype: binary.BigEndian.Uint16(skb.end[12:14]),
		payload:   skb.end[14:],
	}
	copy(hdr.dmac, skb.end[0:6])
	copy(hdr.smac, skb.end[6:12])
	skb.end = skb.end[ETH_HDR_LEN:]
	return hdr
}

func eth_hdr_encode(skb *sk_buff, dev *netdev, dst_hw []byte, ethertype uint16) {
	copy(skb.data[0:6], dst_hw)
	copy(skb.data[6:12], dev.hwaddr[:])
	binary.BigEndian.PutUint16(skb.data[12:14], ethertype)
}
