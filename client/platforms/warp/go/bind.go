package warptransport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type protectedBind struct {
	mutex   sync.Mutex
	socket  *net.UDPConn
	protect func(int) bool
}

type endpoint struct{ netip.AddrPort }

func (value *endpoint) ClearSrc()                {}
func (value *endpoint) SrcToString() string      { return "" }
func (value *endpoint) DstToString() string      { return value.String() }
func (value *endpoint) SrcIP() netip.Addr        { return netip.Addr{} }
func (value *endpoint) DstIP() netip.Addr        { return value.Addr() }
func (value *endpoint) DstToBytes() []byte       { data, _ := value.MarshalBinary(); return data }
func (bind *protectedBind) BatchSize() int       { return 1 }
func (bind *protectedBind) SetMark(uint32) error { return nil }

func (bind *protectedBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().Is4() {
		return nil, errInvalidConfiguration
	}
	return &endpoint{address}, nil
}

func (bind *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	config := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		protected := false
		if err := raw.Control(func(fd uintptr) { protected = bind.protect == nil || bind.protect(int(fd)) }); err != nil {
			return err
		}
		if !protected {
			return errors.New("WARP socket protection failed")
		}
		return nil
	}}
	packet, err := config.ListenPacket(context.Background(), "udp4", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, 0, err
	}
	socket := packet.(*net.UDPConn)
	bind.socket = socket
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		size, source, err := socket.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = size
		endpoints[0] = &endpoint{source}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
}

func (bind *protectedBind) Send(packets [][]byte, destination conn.Endpoint) error {
	bind.mutex.Lock()
	socket := bind.socket
	bind.mutex.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, packet := range packets {
		if _, err := socket.WriteToUDPAddrPort(packet, destination.(*endpoint).AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (bind *protectedBind) Close() error {
	bind.mutex.Lock()
	defer bind.mutex.Unlock()
	if bind.socket == nil {
		return nil
	}
	err := bind.socket.Close()
	bind.socket = nil
	return err
}
