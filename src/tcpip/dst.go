package tcpip

import "log"

func dst_neigh_output(skb *sk_buff) error {
	// struct iphdr *iphdr = ip_hdr(skb);
	// struct netdev *netdev = skb->dev;
	// struct rtentry *rt = skb->rt;
	// uint32_t daddr = ntohl(iphdr->daddr);
	// uint32_t saddr = ntohl(iphdr->saddr);

	// uint8_t *dmac;

	// if (rt->flags & RT_GATEWAY) {
	//     daddr = rt->gateway;
	// }

	// dmac = arp_get_hwaddr(daddr);

	// if (dmac) {
	//     return netdev_transmit(skb, dmac, ETH_P_IP);
	// } else {
	//     arp_request(saddr, daddr, netdev);

	//     /* Inform upper layer that traffic was not sent, retry later */
	//     return -1;
	// }
	log.Println("dst_neigh_output")
	return netdev_transmit(skb, skb.dev.hwaddr, ETH_P_IPV4)
}
