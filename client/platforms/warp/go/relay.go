package warptransport

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	udpIdleTimeout = 60 * time.Second
	maxUDPFlows    = 32
)

func (session *Session) startTCPListener(handle func(net.Conn)) (int, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	if !session.track(listener) {
		return 0, errTransportUnavailable
	}
	session.spawn(func() {
		defer session.release(listener)
		for {
			local, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			if !session.track(local) {
				continue
			}
			if !session.spawn(func() {
				defer session.release(local)
				handle(local)
			}) {
				session.release(local)
				return
			}
		}
	})
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (session *Session) forwardTCP(local net.Conn, target netip.AddrPort) {
	remote, err := session.dial("tcp", target)
	if err != nil {
		return
	}
	if !session.track(remote) {
		return
	}
	defer session.release(remote)
	session.bridge(local, remote)
}

func (session *Session) bridge(local, remote net.Conn) {
	completed := make(chan struct{})
	if !session.spawn(func() {
		defer close(completed)
		_, err := io.CopyBuffer(local, remote, make([]byte, 32*1024))
		if closer, ok := local.(interface{ CloseWrite() error }); ok && err == nil {
			closer.CloseWrite()
		} else {
			local.Close()
		}
	}) {
		return
	}
	_, err := io.CopyBuffer(remote, local, make([]byte, 32*1024))
	if closer, ok := remote.(interface{ CloseWrite() error }); ok && err == nil {
		closer.CloseWrite()
	} else {
		remote.Close()
	}
	<-completed
}

func (session *Session) startUDPRelay(target netip.AddrPort) (int, error) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	if !session.track(listener) {
		return 0, errTransportUnavailable
	}
	session.spawn(func() {
		defer session.release(listener)
		session.forwardUDP(listener, func(data []byte, source netip.AddrPort) (udpRequest, bool) {
			return udpRequest{target: target, payload: data}, source.Addr().IsLoopback()
		})
	})
	return listener.LocalAddr().(*net.UDPAddr).Port, nil
}

type udpRequest struct {
	target  netip.AddrPort
	payload []byte
	prefix  []byte
}

type udpFlowKey struct {
	source netip.AddrPort
	target netip.AddrPort
}

func (session *Session) forwardUDP(listener *net.UDPConn, decode func([]byte, netip.AddrPort) (udpRequest, bool)) {
	var flowsLock sync.Mutex
	flows := make(map[udpFlowKey]net.Conn)
	defer func() {
		flowsLock.Lock()
		defer flowsLock.Unlock()
		for _, flow := range flows {
			flow.Close()
		}
	}()
	buffer := make([]byte, 65535)
	for {
		size, source, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		request, accepted := decode(buffer[:size], source)
		if !accepted {
			continue
		}
		key := udpFlowKey{source, request.target}
		flowsLock.Lock()
		remote := flows[key]
		if remote == nil && len(flows) < maxUDPFlows {
			remote, err = session.dial("udp", request.target)
			if err == nil && session.track(remote) {
				flows[key] = remote
				if !session.spawn(func() {
					defer session.release(remote)
					defer func() {
						flowsLock.Lock()
						delete(flows, key)
						flowsLock.Unlock()
					}()
					response := make([]byte, 65535)
					for {
						remote.SetReadDeadline(time.Now().Add(udpIdleTimeout))
						size, err := remote.Read(response)
						if err != nil {
							return
						}
						if _, err := listener.WriteToUDPAddrPort(append(request.prefix, response[:size]...), source); err != nil {
							return
						}
					}
				}) {
					delete(flows, key)
					session.release(remote)
					remote = nil
				}
			} else {
				remote = nil
			}
		}
		flowsLock.Unlock()
		if remote != nil {
			remote.SetWriteDeadline(time.Now().Add(dialTimeout))
			remote.Write(request.payload)
		}
	}
}
