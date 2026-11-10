// Package live implements a small, bounded, read-only Unix-socket protocol.
// Only aggregate client counters and operational diagnostics cross this socket.
package live

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"dnsmon/internal/packet"
	"dnsmon/internal/store"
)

type Health struct {
	PID             int             `json:"pid"`
	Started         time.Time       `json:"started"`
	Updated         time.Time       `json:"updated"`
	Interface       string          `json:"interface"`
	Port            uint16          `json:"port"`
	LastRequest     time.Time       `json:"last_request"`
	LastFlush       time.Time       `json:"last_flush"`
	FlushDuration   time.Duration   `json:"flush_duration"`
	Flushes         uint64          `json:"flushes"`
	FlushError      string          `json:"flush_error,omitempty"`
	Received        uint64          `json:"received_packets"`
	Counted         uint64          `json:"counted_requests"`
	KernelDrops     uint64          `json:"kernel_drops"`
	PendingIPs      int             `json:"pending_ips"`
	PendingRequests uint64          `json:"pending_requests"`
	Writing         bool            `json:"writing"`
	Backpressure    uint64          `json:"backpressure_waits"`
	TCPFlows        int             `json:"tcp_flows"`
	TCPBytes        int             `json:"tcp_bytes"`
	Fragments       int             `json:"fragment_sets"`
	FragmentBytes   int             `json:"fragment_bytes"`
	RequestedBuffer int             `json:"requested_buffer"`
	ActualBuffer    int             `json:"actual_buffer"`
	RSSBytes        uint64          `json:"rss_bytes"`
	CPUSeconds      float64         `json:"cpu_seconds"`
	Parser          packet.Counters `json:"parser"`
}
type Request struct {
	Op    string `json:"op"`
	Limit int    `json:"limit,omitempty"`
}
type Response struct {
	Health  Health         `json:"health"`
	Totals  store.Totals   `json:"totals"`
	Clients []store.Client `json:"clients,omitempty"`
	Error   string         `json:"error,omitempty"`
	Source  string         `json:"source"`
}

func Path(db string) string { return db + ".sock" }
func Fetch(ctx context.Context, db string, req Request) (Response, error) {
	var r Response
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", Path(db))
	if e != nil {
		return r, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	if e = json.NewEncoder(conn).Encode(req); e != nil {
		return r, e
	}
	if e = json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&r); e != nil {
		return r, e
	}
	if r.Error != "" {
		return r, fmt.Errorf("live monitor: %s", r.Error)
	}
	return r, nil
}

type Server struct {
	listener net.Listener
	path     string
	wg       sync.WaitGroup
}

func Serve(db string, handler func(context.Context, Request) Response) (*Server, error) {
	path := Path(db)
	// Only unlink an old socket, never replace an unrelated file or symlink.
	if st, e := os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	listener, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0660); e != nil {
		listener.Close()
		os.Remove(path)
		return nil, e
	}
	s := &Server{listener: listener, path: path}
	slots := make(chan struct{}, 2)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-slots }()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var req Request
				if json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&req) != nil {
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if req.Op != "health" && req.Op != "top" {
					json.NewEncoder(conn).Encode(Response{Error: "unknown operation"})
					return
				}
				if req.Op == "top" && (req.Limit < 1 || req.Limit > 1000) {
					json.NewEncoder(conn).Encode(Response{Error: "limit must be 1..1000"})
					return
				}
				json.NewEncoder(conn).Encode(handler(ctx, req))
			}()
		}
	}()
	return s, nil
}
func (s *Server) Close() error { e := s.listener.Close(); s.wg.Wait(); os.Remove(s.path); return e }
