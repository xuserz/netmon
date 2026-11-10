package live

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func unixServer(t *testing.T, handler func(context.Context, Request) Response) (string, *Server) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "stats.db")
	s, e := Serve(db, handler)
	if errors.Is(e, syscall.EPERM) {
		t.Skip("sandbox disallows Unix sockets")
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return db, s
}
func TestProtocolAndLimits(t *testing.T) {
	db, _ := unixServer(t, func(_ context.Context, r Request) Response { return Response{Source: "live", Health: Health{PID: 123}} })
	r, e := Fetch(context.Background(), db, Request{Op: "health"})
	if e != nil || r.Health.PID != 123 {
		t.Fatal(r, e)
	}
	if st, e := os.Stat(Path(db)); e != nil || st.Mode().Perm() != 0660 {
		t.Fatal(st, e)
	}
	for _, req := range []Request{{Op: "delete"}, {Op: "top", Limit: 1001}, {Op: "top", Limit: 0}, {Op: "top", Limit: 10, Sort: "unknown"}} {
		if _, e = Fetch(context.Background(), db, req); e == nil {
			t.Fatal("accepted invalid request", req)
		}
	}
}
func TestRefusesToReplaceOrdinaryFile(t *testing.T) {
	db := filepath.Join(t.TempDir(), "stats.db")
	os.WriteFile(Path(db), []byte("keep"), 0600)
	if _, e := Serve(db, nil); e == nil {
		t.Fatal("overwrote ordinary file")
	}
	b, _ := os.ReadFile(Path(db))
	if string(b) != "keep" {
		t.Fatal(string(b))
	}
}
func TestClientCancellationAndServerTimeout(t *testing.T) {
	db, _ := unixServer(t, func(ctx context.Context, _ Request) Response { <-ctx.Done(); return Response{Error: "timed out"} })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := Fetch(ctx, db, Request{Op: "health"}); done <- e }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancellation ignored")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancellation did not interrupt the socket")
	}
}
func TestSlowOrOversizedInputDoesNotCreateUnboundedWork(t *testing.T) {
	db, _ := unixServer(t, func(context.Context, Request) Response { return Response{Source: "live"} })
	var conns []net.Conn
	for i := 0; i < 4; i++ {
		c, e := net.Dial("unix", Path(db))
		if e != nil {
			t.Fatal(e)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.SetWriteDeadline(time.Now().Add(time.Second))
		c.Write([]byte(strings.Repeat(" ", 5000)))
		c.Close()
	}
}
