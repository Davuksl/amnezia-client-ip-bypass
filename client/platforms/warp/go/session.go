package warptransport

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

const (
	dialTimeout       = 10 * time.Second
	handshakeTimeout  = 12 * time.Second
	handshakeLifetime = 180 * time.Second
	maxResources      = 128
)

var errTransportUnavailable = errors.New("WARP transport unavailable")

type Session struct {
	ctx           context.Context
	cancel        context.CancelFunc
	device        *device.Device
	peer          *device.Peer
	network       *netstack.Net
	plan          *transportPlan
	configuration string
	state         atomic.Int32
	operation     sync.Mutex
	resourcesLock sync.Mutex
	resources     map[io.Closer]struct{}
	workers       sync.WaitGroup
	closeOnce     sync.Once
	closed        bool
	port          int
	deadline      time.Time
	lastHandshake int64
	attempt       int
}

func Start(underlayJSON, protocol, configurationJSON string, protect func(int) bool) (*Session, error) {
	plan, err := parsePlan(underlayJSON, protocol, configurationJSON)
	if err != nil {
		return nil, err
	}
	return startSession(plan, protect)
}

func startSession(plan *transportPlan, protect func(int) bool) (*Session, error) {
	address, _ := netip.ParseAddr(strings.Split(plan.underlay.AWG.Address, "/")[0])
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{address}, nil, 1280)
	if err != nil {
		return nil, errTransportUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		ctx: ctx, cancel: cancel, network: network, plan: plan,
		resources: make(map[io.Closer]struct{}), port: plan.underlay.AWG.Port,
	}
	session.device = device.NewDevice(tunnel, &protectedBind{protect: protect}, device.NewLogger(device.LogLevelSilent, ""))
	configured := false
	defer func() {
		if !configured {
			session.Close()
		}
	}()
	uapi, err := plan.underlay.uapi(plan.targets, session.port)
	if err != nil || session.device.IpcSet(uapi) != nil {
		return nil, errInvalidConfiguration
	}
	publicKey, _ := base64.StdEncoding.DecodeString(plan.underlay.AWG.PublicKey)
	var peerKey device.NoisePublicKey
	copy(peerKey[:], publicKey)
	session.peer = session.device.LookupPeer(peerKey)
	if session.peer == nil || session.device.Up() != nil {
		return nil, errTransportUnavailable
	}
	for _, relay := range plan.relays {
		var port int
		if relay.network == "udp" {
			port, err = session.startUDPRelay(relay.remote)
		} else {
			port, err = session.startTCPListener(func(local net.Conn) { session.forwardTCP(local, relay.remote) })
		}
		if err != nil {
			return nil, errTransportUnavailable
		}
		relay.apply(port)
	}
	if plan.xray != nil {
		port, err := session.startTCPListener(session.handleSOCKS)
		if err != nil || plan.attachSocks(port) != nil {
			return nil, errTransportUnavailable
		}
	}
	configuration, err := json.Marshal(plan.configuration)
	if err != nil {
		return nil, errInvalidConfiguration
	}
	session.configuration = string(configuration)
	session.deadline = time.Now().Add(handshakeTimeout)
	if session.peer.SendHandshakeInitiation(false) != nil {
		return nil, errTransportUnavailable
	}
	session.spawn(session.monitor)
	configured = true
	return session, nil
}

func (session *Session) Configuration() string { return session.configuration }
func (session *Session) State() int32          { return session.state.Load() }

func (session *Session) Rebind() error {
	session.operation.Lock()
	defer session.operation.Unlock()
	if session.ctx.Err() != nil || session.state.Load() < 0 {
		return errTransportUnavailable
	}
	if session.device.BindUpdate() != nil {
		session.fail()
		return errTransportUnavailable
	}
	session.beginHandshake()
	return nil
}

func (session *Session) beginHandshake() {
	if configuration, err := session.device.IpcGet(); err == nil {
		session.lastHandshake = handshakeTimestamp(configuration)
	}
	session.state.Store(0)
	session.attempt = 0
	session.deadline = time.Now().Add(handshakeTimeout)
	session.peer.ExpireCurrentKeypairs()
	session.peer.SendHandshakeInitiation(false)
}

func handshakeTimestamp(configuration string) int64 {
	var seconds, nanoseconds int64
	for _, line := range strings.Split(configuration, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "last_handshake_time_sec":
			seconds, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	return seconds*int64(time.Second) + nanoseconds
}

func (session *Session) monitor() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-session.ctx.Done():
			return
		case now := <-ticker.C:
			session.operation.Lock()
			if session.ctx.Err() != nil {
				session.operation.Unlock()
				return
			}
			session.checkHandshake(now)
			failed := session.state.Load() < 0
			session.operation.Unlock()
			if failed {
				return
			}
		}
	}
}

func (session *Session) checkHandshake(now time.Time) {
	configuration, err := session.device.IpcGet()
	if err != nil {
		session.fail()
		return
	}
	handshake := handshakeTimestamp(configuration)
	if handshake > session.lastHandshake {
		session.lastHandshake = handshake
		session.state.Store(1)
	} else if session.state.Load() == 1 && now.Sub(time.Unix(0, handshake)) > handshakeLifetime {
		session.beginHandshake()
	} else if session.state.Load() == 0 && now.After(session.deadline) {
		if session.attempt != 0 {
			session.fail()
			return
		}
		session.attempt++
		if session.port == 500 {
			session.port = session.plan.underlay.AWG.Port
		} else {
			session.port = 500
		}
		publicKey, _ := base64.StdEncoding.DecodeString(session.plan.underlay.AWG.PublicKey)
		endpoint := net.JoinHostPort(session.plan.underlay.AWG.Endpoint, strconv.Itoa(session.port))
		if session.device.IpcSet("public_key="+hex.EncodeToString(publicKey)+"\nendpoint="+endpoint+"\n") != nil {
			session.fail()
			return
		}
		session.deadline = now.Add(handshakeTimeout)
		session.peer.ExpireCurrentKeypairs()
		session.peer.SendHandshakeInitiation(false)
	}
}

func (session *Session) fail() {
	session.state.Store(-1)
	session.device.Down()
}

func (session *Session) dial(network string, remote netip.AddrPort) (net.Conn, error) {
	if session.ctx.Err() != nil || session.state.Load() != 1 {
		return nil, errTransportUnavailable
	}
	if network == "udp" {
		return session.network.DialUDPAddrPort(netip.AddrPort{}, remote)
	}
	ctx, cancel := context.WithTimeout(session.ctx, dialTimeout)
	defer cancel()
	return session.network.DialContextTCPAddrPort(ctx, remote)
}

func (session *Session) track(resource io.Closer) bool {
	session.resourcesLock.Lock()
	defer session.resourcesLock.Unlock()
	if session.closed || len(session.resources) >= maxResources {
		resource.Close()
		return false
	}
	session.resources[resource] = struct{}{}
	return true
}

func (session *Session) release(resource io.Closer) {
	session.resourcesLock.Lock()
	delete(session.resources, resource)
	session.resourcesLock.Unlock()
	resource.Close()
}

func (session *Session) spawn(work func()) bool {
	session.resourcesLock.Lock()
	defer session.resourcesLock.Unlock()
	if session.closed {
		return false
	}
	session.workers.Add(1)
	go func() {
		defer session.workers.Done()
		work()
	}()
	return true
}

func (session *Session) Close() {
	session.closeOnce.Do(func() {
		session.cancel()
		session.operation.Lock()
		session.state.Store(-1)
		session.device.Down()
		session.operation.Unlock()
		session.resourcesLock.Lock()
		session.closed = true
		resources := make([]io.Closer, 0, len(session.resources))
		for resource := range session.resources {
			resources = append(resources, resource)
		}
		clear(session.resources)
		session.resourcesLock.Unlock()
		for _, resource := range resources {
			resource.Close()
		}
		session.workers.Wait()
		session.operation.Lock()
		session.device.Close()
		session.operation.Unlock()
	})
}
