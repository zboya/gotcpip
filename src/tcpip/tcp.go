package tcpip

import (
	"encoding/binary"
	"math/rand"
	"time"
)

const (
	TCP_HDR_LEN = 20
)

const (
	TCP_FIN = 0x01
	TCP_SYN = 0x02
	TCP_RST = 0x04
	TCP_PSH = 0x08
	TCP_ACK = 0x10

	TCP_URG = 0x20
	TCP_ECN = 0x40
	TCP_WIN = 0x80
)

/*
https://tools.ietf.org/html/rfc793

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type tcphdr struct {
	sport       uint16
	dport       uint16
	seq         uint32
	ack_seq     uint32
	data_offset uint8
	rsvd        uint8
	// flags
	//  fin : 1 ,
	//  syn : 1,
	//  rst : 1,
	//  psh : 1,
	//  ack : 1,
	//  urg : 1,
	//  ece : 1,
	//  cwr : 1;
	flags uint8
	win   uint16
	csum  uint16
	urp   uint16
	data  []byte
}

type tcp_options struct {
	options uint16
	mss     uint16
}

type tcp_opt_mss struct {
	kind uint8
	len  uint8
	mss  uint16
}

// transmit control block
type tcb struct {
	snd_una uint32 /* oldest unacknowledged sequence number */
	snd_nxt uint32 /* next sequence number to be sent */
	snd_wnd uint32
	snd_up  uint32
	snd_wl1 uint32
	snd_wl2 uint32
	iss     uint32
	rcv_nxt uint32 /* next sequence number expected on an incoming segments, and
	   is the left or lower edge of the receive window */
	rcv_wnd uint32
	rcv_up  uint32
	irs     uint32
}

type tcp_sock struct {
	// struct sock sk;
	sk             *sock
	fd             int
	tcp_header_len uint16
	tcb            tcb
	flags          uint8
	backoff        uint8
	srtt           int32
	rttvar         int32
	rto            uint32
	// struct timer *retransmit;
	// struct timer *delack;
	// struct timer *keepalive;
	// struct timer *linger;
	delacks  uint8
	rmss     uint16
	smss     uint16
	cwnd     uint16
	inflight uint32

	// struct sk_buff_head ofo_queue; /* Out-of-order queue */
}

const (
	TCP_LISTEN = iota /* represents waiting for a connection request from any remote
	   TCP and port. */
	TCP_SYN_SENT /* represents waiting for a matching connection request
	   after having sent a connection request. */
	TCP_SYN_RECEIVED /* represents waiting for a confirming connection
	   request acknowledgment after having both received and sent a
	   connection request. */
	TCP_ESTABLISHED /* represents an open connection, data received can be
	   delivered to the user.  The normal state for the data transfer phase
	   of the connection. */
	TCP_FIN_WAIT_1 /* represents waiting for a connection termination request
	   from the remote TCP, or an acknowledgment of the connection
	   termination request previously sent. */
	TCP_FIN_WAIT_2 /* represents waiting for a connection termination request
	   from the remote TCP. */
	TCP_CLOSE      /* represents no connection state at all. */
	TCP_CLOSE_WAIT /* represents waiting for a connection termination request
	   from the local user. */
	TCP_CLOSING /* represents waiting for a connection termination request
	   acknowledgment from the remote TCP. */
	TCP_LAST_ACK /* represents waiting for an acknowledgment of the
	   connection termination request previously sent to the remote TCP
	   (which includes an acknowledgment of its connection termination
	   request). */
	TCP_TIME_WAIT /* represents waiting for enough time to pass to be sure
	   the remote TCP received the acknowledgment of its connection
	   termination request. */
)

func (t *tcp_sock) protocol() string {
	return "tcp"
}

func tcphdr_decode(skb *sk_buff) *tcphdr {
	skb.head = skb.end[0:]
	tcph := &tcphdr{
		sport:       binary.BigEndian.Uint16(skb.end[0:2]),
		dport:       binary.BigEndian.Uint16(skb.end[2:4]),
		seq:         binary.BigEndian.Uint32(skb.end[4:8]),
		ack_seq:     binary.BigEndian.Uint32(skb.end[8:12]),
		data_offset: skb.end[12] >> 4,
		rsvd:        skb.end[12] & 0x0f,
		flags:       skb.end[13],
		win:         binary.BigEndian.Uint16(skb.end[14:16]),
		csum:        binary.BigEndian.Uint16(skb.end[16:18]),
		urp:         binary.BigEndian.Uint16(skb.end[18:20]),
		data:        skb.end[20:],
	}
	skb.end = skb.end[20:]
	return tcph
}

func tcphdr_encode(skb *sk_buff, th *tcphdr) {
	binary.BigEndian.PutUint16(skb.head[0:2], th.sport)
	binary.BigEndian.PutUint16(skb.head[2:4], th.dport)
	binary.BigEndian.PutUint32(skb.head[4:8], th.seq)
	binary.BigEndian.PutUint32(skb.head[8:12], th.ack_seq)
	skb.head[12] = 5 << 4
	skb.head[13] = th.flags
	binary.BigEndian.PutUint16(skb.head[14:16], th.win)
	binary.BigEndian.PutUint16(skb.head[18:20], th.urp)
	csum := tcpipChecksum(skb.head[0:20], 0)
	binary.BigEndian.PutUint16(skb.head[16:18], csum)
	// TODO: deal with payload
}

// func connect(addr string) error {
// 	return nil
// }

func generate_iss() uint32 {
	rand.Seed(time.Now().UnixNano())
	return rand.Uint32()
}

func tcp_alloc_skb(optsLen int, size int) *sk_buff {
	reserved := ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + optsLen + size
	skb := alloc_skb(reserved)
	skb.protocol = IP_TCP
	skb.dlen = uint32(size)
	return skb
}

func tcp_set_state(sk *sock, state int) {
	sk.state = state
}
