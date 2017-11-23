package tcpip

import (
	"encoding/binary"
)

/*
https://tools.ietf.org/html/rfc768

0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...

	 User Datagram Header Format
*/

type udphdr struct {
	sport  uint16
	dport  uint16
	length uint16
	csum   uint16
	data   []byte
}

func udphdr_decode(skb *sk_buff) *udphdr {
	skb.head = skb.end[0:]
	return &udphdr{
		sport:  binary.BigEndian.Uint16(skb.end[0:2]),
		dport:  binary.BigEndian.Uint16(skb.end[2:4]),
		length: binary.BigEndian.Uint16(skb.end[4:6]),
		csum:   binary.BigEndian.Uint16(skb.end[6:8]),
		data:   skb.end[8:],
	}
}
