package tcpip

import (
	"bytes"
	"log"
)

const (
	BUFLEN = 1600
)

const (
	ETH_P_ARP  = 0x806
	ETH_P_ALL  = 0x3
	ETH_P_IPV4 = 0x800
	ETH_P_IPV6 = 0x86dd
)

var rawdev *netdev

type netdev struct {
	addr   []byte
	hwaddr []byte
	mtu    uint32
}

func netdev_alloc(addr []byte, hwaddr []byte, mtu uint32) *netdev {
	rawdev = &netdev{addr, hwaddr, mtu}
	return rawdev
}

func netdev_rx_loop() {
	buf := make([]byte, 1<<16)
	for {
		rn, err := tap.Read(buf)
		if err != nil {
			panic(err)
		}
		// log.Printf("read data: %x\n", buf[:rn])
		skb := alloc_skb(rn)
		copy(skb.data, buf[:rn])
		netdev_receive(skb)
	}
}

func netdev_receive(skb *sk_buff) {
	var err error
	hdr := eth_hdr_decode(skb)
	switch hdr.ethertype {
	case ETH_P_ARP:
		log.Println("rcv arp")
		err = arp_rcv(skb)
		if err != nil {
			log.Println(err)
		}
	case ETH_P_IPV4:
		log.Println("rcv ip")
		err = ip_rcv(skb)
		if err != nil {
			log.Println(err)
		}
	case ETH_P_IPV6:

	default:
		log.Println("unsupport eth type")
	}
}

func netdev_transmit(skb *sk_buff, dst_hw []byte, ethertype uint16) error {
	dev := skb.dev
	eth_hdr_encode(skb, dev, dst_hw, ethertype)
	_, err := tap.Write(skb.data)
	if err != nil {
		return err
	}
	return nil
}

func netdev_get(sip []byte) *netdev {
	if !bytes.Equal(sip, rawdev.addr) {
		log.Printf("ip is not equal")
	}
	return rawdev
}

func NetdevRxLoop() {
	netdev_rx_loop()
}

func NewNetdev(addr []byte, hwaddr []byte, mtu uint32) *netdev {
	return netdev_alloc(addr, hwaddr, mtu)
}
