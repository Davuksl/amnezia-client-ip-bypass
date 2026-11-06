package warptransport

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func readSOCKSAddress(reader io.Reader) (string, int, error) {
	var kind [1]byte
	if _, err := io.ReadFull(reader, kind[:]); err != nil {
		return "", 0, err
	}
	var size int
	switch kind[0] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", 0, err
		}
		size = int(length[0])
	default:
		return "", 0, errInvalidConfiguration
	}
	if size == 0 {
		return "", 0, errInvalidConfiguration
	}
	address := make([]byte, size)
	var port [2]byte
	if _, err := io.ReadFull(reader, address); err != nil {
		return "", 0, err
	}
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", 0, err
	}
	host := string(address)
	if kind[0] != 3 {
		host = net.IP(address).String()
	}
	return host, int(binary.BigEndian.Uint16(port[:])), nil
}

func socksAddress(address netip.AddrPort) []byte {
	ip := address.Addr().Unmap()
	kind := byte(1)
	if ip.Is6() {
		kind = 4
	}
	result := append([]byte{kind}, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(result, address.Port())
}

func writeSOCKSReply(local net.Conn, status byte, address netip.AddrPort) error {
	if !address.IsValid() {
		address = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	_, err := local.Write(append([]byte{5, status, 0}, socksAddress(address)...))
	return err
}

func (session *Session) authenticateSOCKS(local net.Conn) bool {
	var header [2]byte
	if _, err := io.ReadFull(local, header[:]); err != nil || header[0] != 5 || header[1] == 0 {
		return false
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(local, methods); err != nil {
		return false
	}
	if !bytes.Contains(methods, []byte{2}) {
		local.Write([]byte{5, 255})
		return false
	}
	if _, err := local.Write([]byte{5, 2}); err != nil {
		return false
	}
	if _, err := io.ReadFull(local, header[:]); err != nil || header[0] != 1 || header[1] == 0 {
		return false
	}
	username := make([]byte, header[1])
	var length [1]byte
	if _, err := io.ReadFull(local, username); err != nil {
		return false
	}
	if _, err := io.ReadFull(local, length[:]); err != nil || length[0] == 0 {
		return false
	}
	password := make([]byte, length[0])
	if _, err := io.ReadFull(local, password); err != nil {
		return false
	}
	accepted := subtle.ConstantTimeCompare(username, []byte(session.plan.username)) &
		subtle.ConstantTimeCompare(password, []byte(session.plan.password))
	status := byte(1)
	if accepted == 1 {
		status = 0
	}
	if _, err := local.Write([]byte{1, status}); err != nil {
		return false
	}
	return accepted == 1
}

func (session *Session) allowedTarget(host string, port int) (netip.AddrPort, bool) {
	target, found := session.plan.targets[net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))]
	return target, found
}

func (session *Session) handleSOCKS(local net.Conn) {
	local.SetDeadline(time.Now().Add(dialTimeout))
	if !session.authenticateSOCKS(local) {
		return
	}
	var request [3]byte
	if _, err := io.ReadFull(local, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	host, port, err := readSOCKSAddress(local)
	if err != nil {
		writeSOCKSReply(local, 8, netip.AddrPort{})
		return
	}
	if request[1] == 3 {
		address, err := netip.ParseAddr(host)
		if err != nil || (!address.IsUnspecified() && !address.IsLoopback()) {
			writeSOCKSReply(local, 2, netip.AddrPort{})
			return
		}
		session.handleSOCKSUDP(local, port)
		return
	}
	if request[1] != 1 {
		writeSOCKSReply(local, 7, netip.AddrPort{})
		return
	}
	target, allowed := session.allowedTarget(host, port)
	if !allowed {
		writeSOCKSReply(local, 2, netip.AddrPort{})
		return
	}
	remote, err := session.dial("tcp", target)
	if err != nil {
		writeSOCKSReply(local, 4, netip.AddrPort{})
		return
	}
	if !session.track(remote) {
		return
	}
	defer session.release(remote)
	if writeSOCKSReply(local, 0, netip.AddrPort{}) != nil {
		return
	}
	local.SetDeadline(time.Time{})
	session.bridge(local, remote)
}

func (session *Session) handleSOCKSUDP(control net.Conn, requestedPort int) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil || !session.track(listener) {
		writeSOCKSReply(control, 1, netip.AddrPort{})
		return
	}
	defer session.release(listener)
	if writeSOCKSReply(control, 0, listener.LocalAddr().(*net.UDPAddr).AddrPort()) != nil {
		return
	}
	if !session.spawn(func() { session.forwardSOCKSUDP(listener, requestedPort) }) {
		return
	}
	control.SetDeadline(time.Time{})
	io.Copy(io.Discard, control)
}

func (session *Session) forwardSOCKSUDP(listener *net.UDPConn, requestedPort int) {
	var source netip.AddrPort
	session.forwardUDP(listener, func(data []byte, client netip.AddrPort) (udpRequest, bool) {
		if !client.Addr().IsLoopback() || (source.IsValid() && client != source) ||
			(requestedPort != 0 && int(client.Port()) != requestedPort) || len(data) < 4 ||
			data[0] != 0 || data[1] != 0 || data[2] != 0 {
			return udpRequest{}, false
		}
		reader := bytes.NewReader(data[3:])
		host, port, err := readSOCKSAddress(reader)
		if err != nil {
			return udpRequest{}, false
		}
		target, allowed := session.allowedTarget(host, port)
		if !allowed {
			return udpRequest{}, false
		}
		source = client
		return udpRequest{target, data[len(data)-reader.Len():], append([]byte{0, 0, 0}, socksAddress(target)...)}, true
	})
}
