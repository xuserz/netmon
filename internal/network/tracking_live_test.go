package network

import (
	"net"
	"os"
	"testing"
	"time"

	"netmon/internal/capture"
	"netmon/internal/observation"
)

func TestLiveTrackingSeparatesIncomingRequestsAndMatchedReplies(t *testing.T) {
	if os.Getenv("NETMON_INTEGRATION") != "1" {
		t.Skip("enable NETMON_INTEGRATION=1 in an isolated network namespace")
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	sock, e := capture.OpenNetworkTracking("lo", 1)
	if e != nil {
		t.Fatal(e)
	}
	defer sock.Close()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
	client, e := dialer.Dial("tcp4", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	server.SetWriteDeadline(time.Now().Add(time.Second))
	if _, e = server.Write([]byte("test reply")); e != nil {
		t.Fatal(e)
	}
	flows := newFlowTracker(32, time.Minute)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	outgoing, inbound, replies := 0, 0, 0
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		raw, at, e := sock.Next()
		if e != nil {
			t.Fatal(e)
		}
		if len(raw) == 0 {
			continue
		}
		p, e := observation.Decode(raw)
		if e != nil || p.Protocol != 6 || (p.Port != port && p.SourcePort != port) {
			continue
		}
		class := flows.Observe(p, sock.Outgoing, at)
		if sock.Outgoing {
			outgoing++
			if !p.SYN {
				t.Fatal("egress TCP data/ACK escaped the header filter")
			}
		} else if class == observation.Inbound {
			inbound++
		} else if class == observation.Reply {
			replies++
		}
		if outgoing > 0 && inbound > 0 && replies > 0 {
			return
		}
	}
	t.Fatalf("direction evidence missing: outgoing=%d inbound=%d replies=%d", outgoing, inbound, replies)
}
