package main

import (
	"log"
	"net"
	"tcpip"
)

const (
	tapaddr  = "10.10.1.5"
	taproute = "10.10.1.0/24"
	tapName  = "tap0"
)

var tapip = []byte{10, 10, 1, 4}

func main() {
	log.SetFlags(log.Lshortfile)
	tap := tcpip.NewTap(tapName)
	err := tap.Open()
	if err != nil {
		panic(err)
	}
	err = tap.SetUp()
	if err != nil {
		panic(err)
	}
	err = tap.SetAddress(tapaddr)
	if err != nil {
		log.Println(err)
	}
	err = tap.SetRouter(taproute)
	if err != nil {
		log.Println(err)
	}

	ifc, err := net.InterfaceByName(tapName)
	if err != nil {
		log.Println(err)
	}
	tcpip.NewNetdev(tapip, ifc.HardwareAddr, 1500)
	tcpip.NetdevRxLoop()
}
