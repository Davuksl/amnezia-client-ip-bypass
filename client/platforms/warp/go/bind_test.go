package warptransport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

func TestProtectedBindRejectsUnprotectedSocket(t *testing.T) {
	called := false
	bind := &protectedBind{protect: func(fd int) bool { called = true; return false }}
	if _, _, err := bind.Open(0); err == nil || !called || bind.socket != nil {
		t.Fatal("unprotected socket was opened")
	}
	bind.Close()
}

func TestProtectedBindSendReceiveReopenAndCleanup(t *testing.T) {
	protected := 0
	bind := &protectedBind{protect: func(fd int) bool { protected++; return true }}
	t.Cleanup(func() { bind.Close() })
	receivers, port, err := bind.Open(0)
	if err != nil || port == 0 || protected != 1 || len(receivers) != 1 {
		t.Fatal("failed to open protected bind")
	}
	if _, _, err := bind.Open(0); err != conn.ErrBindAlreadyOpen {
		t.Fatal("duplicate bind was accepted")
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	target, err := bind.ParseEndpoint(peer.LocalAddr().String())
	if err != nil || bind.Send([][]byte{[]byte("first"), []byte("second")}, target) != nil {
		t.Fatal("failed to send")
	}
	buffer := make([]byte, 32)
	for _, expected := range []string{"first", "second"} {
		size, source, err := peer.ReadFromUDP(buffer)
		if err != nil || string(buffer[:size]) != expected {
			t.Fatal("incorrect UDP packet")
		}
		peer.WriteToUDP([]byte(expected), source)
		packets := [][]byte{make([]byte, 32)}
		sizes := make([]int, 1)
		endpoints := make([]conn.Endpoint, 1)
		count, err := receivers[0](packets, sizes, endpoints)
		if err != nil || count != 1 || !bytes.Equal(packets[0][:sizes[0]], []byte(expected)) ||
			endpoints[0].DstToString() != peer.LocalAddr().String() {
			t.Fatal("incorrect protected receive")
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := receivers[0]([][]byte{make([]byte, 32)}, make([]int, 1), make([]conn.Endpoint, 1))
		done <- err
	}()
	bind.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed receive succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not unblock receive")
	}
	if _, _, err := bind.Open(port); err != nil || protected != 2 {
		t.Fatal("reopened socket was not protected")
	}
	if _, err := bind.ParseEndpoint("[2001:db8::1]:443"); err == nil {
		t.Fatal("accepted unsupported outer IPv6 endpoint")
	}
}
