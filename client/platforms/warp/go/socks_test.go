package warptransport

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func socksEndpoint(t *testing.T, session *Session) string {
	t.Helper()
	var configuration map[string]any
	json.Unmarshal([]byte(session.Configuration()), &configuration)
	var xray map[string]any
	json.Unmarshal([]byte(configuration["config"].(string)), &xray)
	outbounds := xray["outbounds"].([]any)
	proxy := outbounds[len(outbounds)-1].(map[string]any)
	server := proxy["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	return net.JoinHostPort(server["address"].(string), strconv.Itoa(int(server["port"].(float64))))
}

func socksAuthenticate(t *testing.T, connection net.Conn, username, password string, accepted bool) {
	t.Helper()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	connection.Write([]byte{5, 2, 0, 2})
	var response [2]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil || response != [2]byte{5, 2} {
		t.Fatal("SOCKS did not require password authentication")
	}
	message := append([]byte{1, byte(len(username))}, []byte(username)...)
	message = append(message, byte(len(password)))
	message = append(message, []byte(password)...)
	connection.Write(message)
	if _, err := io.ReadFull(connection, response[:]); err != nil || response[0] != 1 || (response[1] == 0) != accepted {
		t.Fatal("incorrect authentication result")
	}
}

func socksRequest(t *testing.T, connection net.Conn, command byte, address []byte) (byte, netip.AddrPort) {
	t.Helper()
	if _, err := connection.Write(append([]byte{5, command, 0}, address...)); err != nil {
		t.Fatal(err)
	}
	var header [3]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil || header[0] != 5 || header[2] != 0 {
		t.Fatal("invalid SOCKS reply")
	}
	host, port, err := readSOCKSAddress(connection)
	if err != nil {
		t.Fatal(err)
	}
	return header[1], netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func TestSOCKSRejectsMissingOrWrongAuthentication(t *testing.T) {
	fixture := createTransportFixture(t)
	session := startFixtureSession(t, fixture, "xray", xrayConfiguration(t, "vless", int(fixture.tcp.Port())), func(int) bool { return true })
	connection, err := net.Dial("tcp4", socksEndpoint(t, session))
	if err != nil {
		t.Fatal(err)
	}
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	connection.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil || reply != [2]byte{5, 255} {
		t.Fatal("SOCKS accepted unauthenticated method")
	}
	connection.Close()
	connection, err = net.Dial("tcp4", socksEndpoint(t, session))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	socksAuthenticate(t, connection, session.plan.username, "incorrect-password", false)
}

func TestSOCKSConnectOnlyAllowsPinnedVPNServer(t *testing.T) {
	fixture := createTransportFixture(t)
	session := startFixtureSession(t, fixture, "xray", xrayConfiguration(t, "vless", int(fixture.tcp.Port())), func(int) bool { return true })
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
	for _, allowed := range []bool{false, true} {
		connection, err := net.Dial("tcp4", socksEndpoint(t, session))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		socksAuthenticate(t, connection, session.plan.username, session.plan.password, true)
		target := fixture.tcp
		if !allowed {
			target = netip.MustParseAddrPort("198.51.100.3:443")
		}
		status, _ := socksRequest(t, connection, 1, socksAddress(target))
		if !allowed {
			if status != 2 {
				t.Fatal("unrelated destination was allowed")
			}
			continue
		}
		if status != 0 {
			t.Fatal("pinned destination was rejected")
		}
		connection.Write([]byte("socks-tcp"))
		response := make([]byte, 9)
		if _, err := io.ReadFull(connection, response); err != nil || string(response) != "socks-tcp" {
			t.Fatal("SOCKS TCP payload was not preserved")
		}
	}
}

func TestSOCKSUDPAssociateEnforcesTargetsSourceAndCleanup(t *testing.T) {
	fixture := createTransportFixture(t)
	session := startFixtureSession(t, fixture, "ssxray", xrayConfiguration(t, "shadowsocks", int(fixture.udp.Port())), func(int) bool { return true })
	waitUntil(t, 10*time.Second, func() bool { return session.State() == 1 })
	control, err := net.Dial("tcp4", socksEndpoint(t, session))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	socksAuthenticate(t, control, session.plan.username, session.plan.password, true)
	status, relay := socksRequest(t, control, 3, socksAddress(netip.AddrPortFrom(netip.IPv4Unspecified(), 0)))
	if status != 0 || !relay.Addr().IsLoopback() {
		t.Fatal("UDP association failed")
	}
	client, err := net.Dial("udp4", relay.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := bytes.Repeat([]byte("udp"), 1400)
	prefix := append([]byte{0, 0, 0}, socksAddress(fixture.udp)...)
	packet := append(prefix, payload...)
	client.SetDeadline(time.Now().Add(5 * time.Second))
	client.Write(packet)
	response := make([]byte, 65535)
	size, err := client.Read(response)
	if err != nil || !bytes.Equal(response[:size], packet) {
		t.Fatalf("SOCKS UDP payload was not preserved: %v", err)
	}
	for _, rejected := range [][]byte{append([]byte{0, 0, 1}, packet[3:]...),
		append(append([]byte{0, 0, 0}, socksAddress(netip.MustParseAddrPort("198.51.100.3:443"))...), payload...)} {
		client.SetDeadline(time.Now().Add(150 * time.Millisecond))
		client.Write(rejected)
		if _, err := client.Read(response); err == nil {
			t.Fatal("fragmented or unrelated SOCKS UDP target was accepted")
		}
	}
	other, err := net.Dial("udp4", relay.String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetDeadline(time.Now().Add(150 * time.Millisecond))
	other.Write(packet)
	if _, err := other.Read(response); err == nil {
		t.Fatal("UDP association was hijacked by another local source")
	}
	control.Close()
	waitUntil(t, 3*time.Second, func() bool {
		session.resourcesLock.Lock()
		defer session.resourcesLock.Unlock()
		return len(session.resources) == 1
	})
}

func TestSOCKSAddressParsing(t *testing.T) {
	for _, target := range []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:443"), netip.MustParseAddrPort("[2001:db8::2]:1194")} {
		host, port, err := readSOCKSAddress(bytes.NewReader(socksAddress(target)))
		if err != nil || host != target.Addr().String() || port != int(target.Port()) {
			t.Fatal("SOCKS IP address round trip failed")
		}
	}
	domain := binary.BigEndian.AppendUint16(append([]byte{3, 11}, []byte("vpn.example")...), 443)
	host, port, err := readSOCKSAddress(bytes.NewReader(domain))
	if err != nil || host != "vpn.example" || port != 443 {
		t.Fatal("SOCKS domain parsing failed")
	}
	for _, invalid := range [][]byte{{0}, {3, 0}, {1, 127}, {4, 0}} {
		if _, _, err := readSOCKSAddress(bytes.NewReader(invalid)); err == nil {
			t.Fatal("truncated SOCKS address was accepted")
		}
	}
}
