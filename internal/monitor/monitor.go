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

	"dnsmon/internal/capture"
	"dnsmon/internal/config"
	"dnsmon/internal/packet"
	"dnsmon/internal/store"
	"golang.org/x/sys/unix"
)

func Run(ctx context.Context, c config.Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(c.Database), 0750); e != nil {
		return e
	}
	// The lock contains no statistics and prevents two monitors on this DB.
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
		return e
	}
	defer db.Close()
	sock, e := capture.Open(c.Interface, c.Port, c.SocketBufferMB)
	if e != nil {
		return e
	}
	defer sock.Close()
	log.Printf("monitoring interface=%s port=%d destination=%q receive_buffer=%d database=%s", c.Interface, c.Port, c.Destination, sock.BufferBytes, c.Database)
	if sock.BufferBytes < c.SocketBufferMB<<20 {
		log.Printf("WARNING: kernel capped SO_RCVBUF; increase net.core.rmem_max if drops occur")
	}
	return consume(ctx, c, db, sock)
}

type source interface {
	Read([]byte) (int, error)
	Drops() (uint32, error)
}

func consume(ctx context.Context, c config.Config, db *store.Store, sock source) error {
	var e error
	var dst netip.Addr
	if c.Destination != "" {
		dst, _ = netip.ParseAddr(c.Destination)
	}
	batch := make(map[netip.Addr]store.Delta)
	engine := packet.New(c.Port, dst, packet.Limits{Flows: c.MaxTCPFlows, TCPBytes: c.MaxTCPBytes, Fragments: c.MaxFragments, FragmentBytes: c.MaxFragmentBytes, Timeout: c.ReassemblyTimeout}, nil)
	var flushErr error
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := db.Flush(batch); err != nil {
			return err
		}
		clear(batch)
		return nil
	}
	engine.Count = func(ip netip.Addr, n, ts int64) {
		if flushErr != nil {
			return
		}
		if _, ok := batch[ip]; !ok && len(batch) >= c.MaxPending {
			flushErr = flush()
			if flushErr != nil {
				return
			}
		}
		store.Add(batch, ip, n, ts)
	}

	nextFlush := time.Now().Add(c.FlushInterval)
	nextHealth := time.Now().Add(time.Second * 10)
	var previous packet.Counters
	buf := make([]byte, 65575)
	for {
		if ctx.Err() != nil {
			if e = flush(); e != nil {
				return fmt.Errorf("shutdown flush: %w", e)
			}
			log.Print("stopped; pending counters committed")
			return nil
		}
		n, readErr := sock.Read(buf)
		now := time.Now()
		if readErr != nil {
			return errors.Join(readErr, flush())
		}
		if n > 0 {
			engine.Feed(buf[:n], now)
		}
		if flushErr != nil {
			return fmt.Errorf("monitor stopped, uncommitted counters remain volatile: %w", flushErr)
		}
		if !now.Before(nextFlush) {
			if e = flush(); e != nil {
				return e
			}
			nextFlush = now.Add(c.FlushInterval)
		}
		if !now.Before(nextHealth) {
			engine.Expire(now)
			dropped, err := sock.Drops()
			if err != nil {
				return errors.Join(err, flush())
			}
			if dropped > 0 {
				log.Printf("WARNING: kernel dropped %d packets; totals may be incomplete", dropped)
			}
			if engine.Counters != previous {
				log.Printf("WARNING: parser totals: malformed=%d fragment_discarded=%d tcp_discarded=%d midstream_segments=%d; totals may be incomplete", engine.Counters.Malformed, engine.Counters.FragmentDiscarded, engine.Counters.TCPDiscarded, engine.Counters.Midstream)
				previous = engine.Counters
			}
			nextHealth = now.Add(10 * time.Second)
		}
	}
}
