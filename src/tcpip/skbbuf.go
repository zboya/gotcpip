package tcpip

type sk_buff struct {
	// struct list_head list;
	// struct rtentry *rt;
	dev      *netdev
	refcnt   int
	protocol uint16
	len      uint32
	dlen     uint32
	seq      uint32
	end_seq  uint32
	end      []byte
	head     []byte
	data     []byte
	payload  []byte
}

func alloc_skb(size int) *sk_buff {
	skb := &sk_buff{
		refcnt: 0,
		data:   make([]byte, size),
	}

	skb.head = skb.data
	skb.end = skb.data

	// list_init(&skb->list);

	return skb
}
