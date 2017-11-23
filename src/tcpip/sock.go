package tcpip

import (
	"container/list"
	"net"
)

type sock struct {
	network string
	addr    string
	state   int
	sport   uint16
	dport   uint16
	saddr   net.IP
	daddr   net.IP

	tsk           *tcp_sock
	receive_queue *list.List
	write_queue   *list.List
}
