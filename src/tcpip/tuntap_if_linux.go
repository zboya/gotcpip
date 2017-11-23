// +build linux
package tcpip

import (
	"errors"
	"os/exec"
	"syscall"
	"unsafe"
)

var tap *Tap

type Tap struct {
	Name string
	fd   int
}

func NewTap(name string) *Tap {
	return &Tap{Name: name}
}

// Open opens the specified TUN device, and
// returns its file descriptor.
func (t *Tap) Open() error {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], t.Name)
	ifr.flags = syscall.IFF_TAP | syscall.IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return errno
	}

	// if err = syscall.SetNonblock(fd, true); err != nil {
	// 	syscall.Close(fd)
	// 	return err
	// }
	t.fd = fd
	tap = t
	return nil
}

func (t *Tap) Read(b []byte) (int, error) {
	return syscall.Read(t.fd, b)
}

func (t *Tap) Write(b []byte) (int, error) {
	return syscall.Write(t.fd, b)
}

func (t *Tap) Close() error {
	return syscall.Close(t.fd)
}

func (t *Tap) SetRouter(r string) error {
	info, err := exec.Command("ip", "route", "add", "dev", t.Name, r).CombinedOutput()
	if err != nil {
		return errors.New(err.Error() + " " + string(info))
	}
	return nil
}

func (t *Tap) SetAddress(addr string) error {
	info, err := exec.Command("ip", "address", "add", "dev", t.Name, "local", addr).CombinedOutput()
	if err != nil {
		return errors.New(err.Error() + " " + string(info))
	}
	return nil
}

//  ("ip link set dev %s up", dev);
func (t *Tap) SetUp() error {
	info, err := exec.Command("ip", "link", "set", "dev", t.Name, "up").CombinedOutput()
	if err != nil {
		return errors.New(err.Error() + " " + string(info))
	}
	return nil
}
