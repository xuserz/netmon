package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/live"
	"dnsmon/internal/store"
)

// Model Docker's veth/bridge path without installing Docker or altering the
// host network/firewall. A packet traverses an ingress veth and its bridge;
// binding the monitor to the ingress must count exactly once, with the peer IP.
func TestLiveBridgeIngressCountsOnce(t *testing.T) {
	if os.Getenv("DNSMON_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root in a user namespace and DNSMON_INTEGRATION=1")
	}
	for _, tool := range []string{"unshare", "ip", "python3"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Skip("missing " + tool)
		}
	}
	ownNS, _ := os.Readlink("/proc/self/ns/net")
	if os.Getenv("DNSMON_BRIDGE_CHILD") != "1" {
		executable, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", executable, "-test.run=^TestLiveBridgeIngressCountsOnce$", "-test.v")
		cmd.Env = append(os.Environ(), "DNSMON_BRIDGE_CHILD=1", "DNSMON_PARENT_NETNS="+ownNS)
		output, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated bridge test: %v\n%s", e, output)
		}
		t.Log(string(output))
		return
	}
	if parent := os.Getenv("DNSMON_PARENT_NETNS"); parent == "" || parent == ownNS {
		t.Fatal("refusing to create test links outside a new network namespace")
	}
	runIP := func(args ...string) {
		t.Helper()
		out, e := exec.Command("ip", args...).CombinedOutput()
		if e != nil {
			t.Fatalf("ip %v: %v %s", args, e, out)
		}
	}
	runIP("link", "set", "lo", "up")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const peerScript = `import socket,subprocess,sys,time
print("ready",flush=True)
sys.stdin.readline()
subprocess.run(["ip","link","set","lo","up"],check=True)
subprocess.run(["ip","addr","add","10.212.0.2/24","dev","dm-client"],check=True)
subprocess.run(["ip","link","set","dm-client","up"],check=True)
q=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(100):
 s.sendto(q,("10.212.0.1",int(sys.argv[1])))
 if i%10==0: time.sleep(.001)
print("sent",flush=True)
sys.stdin.readline()
`
	// Reserve the UDP port after assigning the bridge address, but start the peer
	// namespace first so its PID can receive the second veth endpoint.
	runIP("link", "add", "dm-bridge", "type", "bridge")
	runIP("addr", "add", "10.212.0.1/24", "dev", "dm-bridge")
	runIP("link", "set", "dm-bridge", "up")
	receiver, e := net.ListenPacket("udp4", "10.212.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := receiver.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	port := receiver.LocalAddr().(*net.UDPAddr).Port
	peer := exec.CommandContext(ctx, "unshare", "--net", "python3", "-u", "-c", peerScript, fmt.Sprint(port))
	stdout, e := peer.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := peer.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	peer.Stderr = os.Stderr
	if e = peer.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	output := bufio.NewReader(stdout)
	if line, err := output.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatal("peer startup", line, err)
	}
	runIP("link", "add", "dm-in", "type", "veth", "peer", "name", "dm-client")
	runIP("link", "set", "dm-client", "netns", fmt.Sprint(peer.Process.Pid))
	runIP("link", "set", "dm-in", "master", "dm-bridge")
	runIP("link", "set", "dm-in", "up")
	c := config.Default()
	c.Interface = "dm-in"
	c.Port = uint16(port)
	c.Database = filepath.Join(t.TempDir(), "stats.db")
	monitorCtx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Run(monitorCtx, c) }()
	ready := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := live.Fetch(ctx, c.Database, live.Request{Op: "health"}); err == nil {
			ready = true
			break
		}
		select {
		case err := <-done:
			t.Fatal(err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("monitor did not become ready")
	}
	io.WriteString(stdin, "send\n")
	if line, err := output.ReadString('\n'); err != nil || strings.TrimSpace(line) != "sent" {
		t.Fatal("peer traffic", line, err)
	}
	var metrics live.Health
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r, err := live.Fetch(ctx, c.Database, live.Request{Op: "health"})
		if err == nil {
			metrics = r.Health
			if metrics.Counted >= 100 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if metrics.Counted != 100 || metrics.KernelDrops != 0 {
		t.Fatal("bridge caused loss/duplicate", metrics)
	}
	db, e := store.Open(c.Database, false, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	client, e := store.Scan(db.DB.QueryRow("SELECT ip,requests,first_seen,last_seen FROM clients"))
	if e != nil || client.IP != "10.212.0.2" || client.Requests != 100 {
		t.Fatal(client, e)
	}
	io.WriteString(stdin, "exit\n")
	stdin.Close()
	if e = peer.Wait(); e != nil {
		t.Fatal(e)
	}
}
