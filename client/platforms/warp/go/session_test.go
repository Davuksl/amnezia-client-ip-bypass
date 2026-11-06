package warptransport

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

type transportFixture struct {
	underlay underlayConfiguration
	udp      netip.AddrPort
	tcp      netip.AddrPort
}

func createTransportFixture(t *testing.T) transportFixture {
	t.Helper()
	clientKey := bytes.Repeat([]byte{0x11}, 32)
	serverKey := bytes.Repeat([]byte{0x22}, 32)
	clientPublic, err := curve25519.X25519(clientKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := curve25519.X25519(serverKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("192.0.2.2")
	tunnel, network, err := netstack.CreateNetTUN([]netip.Addr{address}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	bind := &protectedBind{protect: func(int) bool { return true }}
	server := device.NewDevice(tunnel, bind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(server.Close)
	uapi := "private_key=" + hex.EncodeToString(serverKey) + "\ns1=0\ns2=0\nh1=1\nh2=2\nh3=3\nh4=4\n" +
		"public_key=" + hex.EncodeToString(clientPublic) + "\nallowed_ip=192.0.2.1/32\n"
	if server.IpcSet(uapi) != nil || server.Up() != nil {
		t.Fatal("failed to start test AWG peer")
	}
	udp, err := network.ListenUDPAddrPort(netip.AddrPortFrom(address, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			size, source, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp.WriteTo(buffer[:size], source)
		}
	}()
	tcp, err := network.ListenTCPAddrPort(netip.AddrPortFrom(address, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	go func() {
		for {
			connection, err := tcp.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { connection.Close() })
			go func() {
				defer connection.Close()
				io.Copy(connection, connection)
			}()
		}
	}()
	config := testUnderlay()
	config.AWG.PublicKey = base64.StdEncoding.EncodeToString(serverPublic)
	config.AWG.Port = bind.socket.LocalAddr().(*net.UDPAddr).Port
	return transportFixture{config, udp.LocalAddr().(*net.UDPAddr).AddrPort(), tcp.Addr().(*net.TCPAddr).AddrPort()}
}

func startFixtureSession(t *testing.T, fixture transportFixture, protocol, configuration string, protect func(int) bool) *Session {
	t.Helper()
	session, err := Start(jsonText(t, fixture.underlay), protocol, configuration, protect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	return session
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func localEndpoint(t *testing.T, session *Session) string {
	t.Helper()
	var configuration map[string]any
	if json.Unmarshal([]byte(session.Configuration()), &configuration) != nil {
		t.Fatal("invalid rewritten configuration")
	}
	return net.JoinHostPort(configuration["hostName"].(string), strconv.Itoa(int(configuration["port"].(float64))))
}

func TestWireguardRelayTransfersFragmentedUDP(t *testing.T) {
	fixture := createTransportFixture(t)
	session := startFixtureSession(t, fixture, "awg", jsonText(t, map[string]any{
		"hostName": "vpn.example", "port": fixture.udp.Port(), "mtu": "1420",
	}), func(int) bool { return true })
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
	connection, err := net.Dial("udp4", localEndpoint(t, session))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for _, size := range []int{1, 1252, 1312, 4096, 65000} {
		payload := bytes.Repeat([]byte{byte(size % 251)}, size)
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := connection.Write(payload); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 65535)
		count, err := connection.Read(response)
		if err != nil || !bytes.Equal(response[:count], payload) {
			t.Fatalf("UDP payload %d bytes was not preserved: %v", size, err)
		}
	}
}

func TestOpenVPNRelayTransfersTCPAndHalfClose(t *testing.T) {
	fixture := createTransportFixture(t)
	session := startFixtureSession(t, fixture, "openvpn", jsonText(t, map[string]any{
		"config": "remote vpn.example " + strconv.Itoa(int(fixture.tcp.Port())) + " tcp-client\n",
	}), func(int) bool { return true })
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
	var configuration map[string]any
	json.Unmarshal([]byte(session.Configuration()), &configuration)
	fields := strings.Fields(configuration["config"].(string))
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort(fields[1], fields[2]), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("tcp-payload"), 30000)
	done := make(chan error, 1)
	go func() {
		_, err := connection.Write(payload)
		if err == nil {
			err = connection.(*net.TCPConn).CloseWrite()
		}
		done <- err
	}()
	response, err := io.ReadAll(connection)
	if err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("TCP relay or half-close failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionRebindProtectsNewSocketAndWaitsForFreshHandshake(t *testing.T) {
	fixture := createTransportFixture(t)
	var protected atomic.Int32
	session := startFixtureSession(t, fixture, "awg", jsonText(t, map[string]any{
		"hostName": "vpn.example", "port": fixture.udp.Port(),
	}), func(int) bool { protected.Add(1); return true })
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
	if session.Rebind() != nil || protected.Load() < 2 || session.State() != 0 {
		t.Fatal("rebind did not protect its socket or invalidate readiness")
	}
	if _, err := session.dial("udp", fixture.udp); err == nil {
		t.Fatal("transport was available before fresh handshake")
	}
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
}

func TestSessionFallbackFailsClosed(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	config := testUnderlay()
	config.AWG.Port = sink.LocalAddr().(*net.UDPAddr).Port
	session, err := Start(jsonText(t, config), "awg", `{"hostName":"vpn.example","port":51820}`, func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	session.operation.Lock()
	now := session.deadline.Add(time.Second)
	session.checkHandshake(now)
	if session.port != 500 || session.State() != 0 || session.attempt != 1 {
		session.operation.Unlock()
		t.Fatal("UDP 500 fallback was not attempted")
	}
	session.checkHandshake(session.deadline.Add(time.Second))
	session.operation.Unlock()
	if session.State() != -1 || session.Rebind() == nil {
		t.Fatal("failed session recovered through direct transport")
	}
	if _, err := session.dial("udp", netip.MustParseAddrPort("192.0.2.2:51820")); err == nil {
		t.Fatal("failed session still allows dialing")
	}
}

func TestSessionRejectsSocketProtectionFailure(t *testing.T) {
	if session, err := Start(jsonText(t, testUnderlay()), "awg", `{"hostName":"vpn.example","port":51820}`,
		func(int) bool { return false }); err == nil || session != nil {
		t.Fatal("unprotected session was started")
	}
}

func TestSessionConcurrentCloseReleasesRelays(t *testing.T) {
	fixture := createTransportFixture(t)
	session := startFixtureSession(t, fixture, "awg", jsonText(t, map[string]any{
		"hostName": "vpn.example", "port": fixture.udp.Port(),
	}), func(int) bool { return true })
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
	var closers sync.WaitGroup
	for range 8 {
		closers.Add(1)
		go func() { defer closers.Done(); session.Close() }()
	}
	closers.Wait()
	session.resourcesLock.Lock()
	remaining := len(session.resources)
	session.resourcesLock.Unlock()
	if session.State() != -1 || remaining != 0 || session.spawn(func() {}) || session.Rebind() == nil {
		t.Fatal("closed session retained live resources")
	}
}

func TestHandshakeTimestamp(t *testing.T) {
	if got := handshakeTimestamp("last_handshake_time_sec=12\nlast_handshake_time_nsec=34\n"); got != 12000000034 {
		t.Fatal("handshake time parsed incorrectly")
	}
	if handshakeTimestamp("last_handshake_time_sec=invalid\n") != 0 {
		t.Fatal("malformed handshake time was accepted")
	}
}
