package tcpip

import "testing"
import "encoding/binary"
import "bytes"

func TestEthHdrDecode(t *testing.T) {
	skb := alloc_skb(BUFLEN)
	dmac := []byte{1, 1, 1, 1, 1, 1}
	smac := []byte{2, 2, 2, 2, 2, 2}
	copy(skb.data[0:6], dmac)
	copy(skb.data[6:12], smac)
	binary.BigEndian.PutUint16(skb.data[12:14], ETH_P_ARP)

	hdr := eth_hdr_decode(skb)
	if !bytes.Equal(dmac, hdr.dmac) {
		t.Error("dmac wrong")
	}
	if !bytes.Equal(smac, hdr.smac) {
		t.Error("smac wrong")
	}
	if hdr.ethertype != ETH_P_ARP {
		t.Error("wrong ethertype")
	}
}
