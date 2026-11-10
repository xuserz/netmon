package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"netmon/internal/capture"
	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/packet"
	"netmon/internal/store"
	"golang.org/x/sys/unix"
)

func Run(ctx context.Context, c config.Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(c.Database), 0750); e != nil {
		return e
	}
	lock, e := os.OpenFile(c.Database+".lock", os.O_CREATE|os.O_RDWR, 0640)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("another monitor holds this database lock")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	db, e := store.Open(c.Database, true, c.MaxDatabaseMB, c.MaxWALMB)
	if e != nil {
		return fmt.Errorf("database: %w", e)
	}
	defer db.Close()
	var federation *cluster.Manager
	if c.Cluster.Enabled {
		federation, e = cluster.New(ctx, c, db)
		if e != nil {
			return fmt.Errorf("cluster: %w", e)
		}
		defer federation.Close()
	}
	b, e := newBatcher(c, db)
	if e != nil {
		return e
	}
	defer b.Close()
	b.cluster = federation
	sock, e := capture.Open(c.Interface, c.Port, c.SocketBufferMB)
	if e != nil {
		return e
	}
	defer sock.Close()
	server, e := live.Serve(c.Database, b.Snapshot)
	if e != nil {
		return fmt.Errorf("diagnostic socket: %w", e)
	}
	defer server.Close()
	log.Printf("monitoring interface=%s port=%d destination=%q backend=tpacket_v3 ring_requested=%d ring_allocated=%d database=%s", c.Interface, c.Port, c.Destination, c.SocketBufferMB<<20, sock.BufferBytes, c.Database)

	e = collect(ctx, c, sock, b, sock.BufferBytes)
	closeErr := b.Close()
	if closeErr == nil {
		log.Print("capture stopped; pending counters committed")
	}
	return errors.Join(e, closeErr)
}

type source interface {
	Read([]byte) (int, error)
	Drops() (uint32, error)
}

func consume(ctx context.Context, c config.Config, db *store.Store, sock source) error {
	b, e := newBatcher(c, db)
	if e != nil {
		return e
	}
	e = collect(ctx, c, sock, b, 0)
	return errors.Join(e, b.Close())
}
func collect(ctx context.Context, c config.Config, sock source, b *batcher, actual int) error {
	var dst netip.Addr
	if c.Destination != "" {
		dst, _ = netip.ParseAddr(c.Destination)
	}
	engine := packet.New(c.Port, dst, packet.Limits{Flows: c.MaxTCPFlows, TCPBytes: c.MaxTCPBytes, Fragments: c.MaxFragments, FragmentBytes: c.MaxFragmentBytes, Timeout: c.ReassemblyTimeout}, nil)
	engine.TCPIdleTimeout = c.TCPIdleTimeout
	var addErr error
	engine.Count = func(ip netip.Addr, n, ts int64) {
		if addErr == nil {
			addErr = b.AddContext(ctx, ip, n, ts)
		}
	}
	nextFlush := time.Now().Add(c.FlushInterval)
	nextHealth := time.Now()
	nextReport := time.Now().Add(10 * time.Second)
	var previous packet.Counters
	var received uint64
	var buf []byte
	reader, mapped := sock.(interface {
		Next() ([]byte, time.Time, error)
	})
	if !mapped {
		buf = make([]byte, 65575)
	}
	b.recordCapture(engine, 0, time.Time{})
	stopHealth := b.startHealth(ctx, sock, actual, mapped)
	defer stopHealth()
	for {
		if ctx.Err() != nil {
			return nil
		}
		var data []byte
		var arrival time.Time
		var e error
		if mapped {
			data, arrival, e = reader.Next()
		} else {
			var n int
			n, e = sock.Read(buf)
			data = buf[:n]
			arrival = time.Now()
		}
		now := time.Now()
		if e != nil {
			return e
		}
		if len(data) > 0 {
			received++
			engine.Feed(data, arrival)
		}
		if addErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("writer failed, pending counters could not be committed: %w", addErr)
		}
		if e = b.Error(); e != nil {
			return e
		}
		if !now.Before(nextFlush) {
			b.Rotate()
			nextFlush = now.Add(c.FlushInterval)
		}
		if !now.Before(nextHealth) {
			engine.Expire(now)
			b.recordCapture(engine, received, arrival)
			nextHealth = now.Add(time.Second)
		}
		if !now.Before(nextReport) {
			if engine.Counters != previous {
				log.Printf("WARNING: parser totals: %+v", engine.Counters)
				previous = engine.Counters
			}
			nextReport = now.Add(10 * time.Second)
		}
	}
}
