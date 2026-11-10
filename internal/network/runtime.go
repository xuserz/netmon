package network

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"netmon/internal/capture"
	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/observation"
)

func RuntimeBase(c config.Config) string { return filepath.Join(c.Network.RuntimeDirectory, "monitor") }

type report struct {
	rows        map[string][]observation.IP
	local       map[string][]observation.IP
	totals      map[string]observation.Totals
	localTotals observation.Totals
	at          time.Time
}
type Runtime struct {
	cfg                       config.Config
	disk                      *disk
	transport                 *transport
	collector                 *collector
	queue                     *memoryQueue
	socket                    *capture.Socket
	cancel                    context.CancelFunc
	wg                        sync.WaitGroup
	healthMu                  sync.Mutex
	health                    live.Health
	report                    atomic.Pointer[report]
	acks, malformed, received atomic.Uint64
	lastPacket                atomic.Int64
}

func newRuntime(c config.Config) (*Runtime, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	name := c.Cluster.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	var key []byte
	var e error
	if c.Cluster.Enabled {
		key, e = cluster.ReadKey(c.Cluster.KeyFile)
		if e != nil {
			return nil, e
		}
	}
	r := &Runtime{cfg: c, queue: newQueue(c.Storage.QueueMemoryMB << 20), health: live.Health{PID: os.Getpid(), Started: time.Now(), Mode: "network", StorageMode: c.Storage.Mode, Interface: c.Interface, RetentionSeconds: int64(c.Storage.Retention / time.Second), RequestedBuffer: c.SocketBufferMB << 20}}
	node := ""
	if c.Storage.Mode == "full" {
		r.disk, e = openDisk(c, true)
		if e != nil {
			return nil, e
		}
		node = r.disk.node
	} else {
		node = forwardIdentity(c, key)
	}
	ok := false
	defer func() {
		if !ok && r.disk != nil {
			r.disk.Close()
		}
	}()
	r.transport, e = newTransport(c, node, name, r.disk)
	if e != nil {
		return nil, e
	}
	r.collector = newCollector(node, name, c.MaxActivityIPs, Policy(c), r.queue)
	r.health.ClusterNode = node
	r.health.ClusterEnabled = c.Cluster.Enabled
	r.report.Store(&report{rows: map[string][]observation.IP{}, local: map[string][]observation.IP{}, totals: map[string]observation.Totals{}, at: time.Now()})
	ok = true
	return r, nil
}
func (r *Runtime) setError(e error) {
	r.healthMu.Lock()
	r.health.ClusterError = limitedError(e)
	r.health.FlushError = limitedError(e)
	r.healthMu.Unlock()
}
func (r *Runtime) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			pending := r.queue.peek(64, r.cfg.Storage.Retention)
			if len(pending) > 0 {
				var e error
				work, stop := context.WithTimeout(ctx, 10*time.Second)
				if r.disk != nil {
					samples := make([]observation.Sample, len(pending))
					for i, p := range pending {
						samples[i] = p.sample
					}
					e = r.disk.Merge(work, samples, nil)
				} else {
					e = r.transport.send(work, pending)
				}
				stop()
				r.setError(e)
				if e == nil {
					r.queue.confirm(pending)
					r.acks.Add(1)
					r.healthMu.Lock()
					r.health.LastFlush = time.Now()
					r.health.Flushes++
					r.healthMu.Unlock()
					continue
				}
				if e != nil {
					timer := time.NewTimer(time.Second)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
					continue
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-r.queue.notify:
			}
		}
	}()
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(cappedInterval(r.cfg.Cluster.SyncInterval))
		defer ticker.Stop()
		for {
			r.transport.sync(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	if r.cfg.Cluster.Enabled {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			ticker := time.NewTicker(r.transport.heartbeatInterval())
			defer ticker.Stop()
			for {
				r.transport.probe(ctx)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			r.publish(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	if r.disk != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				work, stop := context.WithTimeout(ctx, 3*time.Second)
				for {
					n, e := r.disk.Prune(work)
					if e != nil {
						if ctx.Err() == nil {
							r.setError(e)
						}
						break
					}
					if n < 128 || work.Err() != nil {
						break
					}
				}
				stop()
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
}
func cappedInterval(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	return d
}
func (r *Runtime) publish(parent context.Context) {
	now := time.Now()
	local, localTotals := r.collector.snapshot(now)
	snapshot := &report{local: map[string][]observation.IP{}, rows: map[string][]observation.IP{}, localTotals: localTotals, totals: map[string]observation.Totals{}, at: now}
	for _, kind := range []string{"score", "total", "bytes", "syn"} {
		copy := append([]observation.IP(nil), local...)
		sortRows(copy, kind)
		snapshot.local[kind] = copy
	}
	if r.disk != nil {
		work, stop := context.WithTimeout(parent, 750*time.Millisecond)
		success := true
		for _, kind := range []string{"score", "total", "bytes", "syn"} {
			rows, total, e := r.disk.View(work, kind, 1000)
			if e != nil {
				success = false
				break
			}
			snapshot.rows[kind] = rows
			snapshot.totals[kind] = total
		}
		stop()
		if !success {
			old := r.report.Load()
			snapshot.rows = old.rows
			snapshot.totals = old.totals
			snapshot.at = old.at
		}
	} else {
		snapshot.rows = snapshot.local
		for _, kind := range []string{"score", "total", "bytes", "syn"} {
			snapshot.totals[kind] = localTotals
		}
	}
	r.report.Store(snapshot)
	var usage unix.Rusage
	unix.Getrusage(unix.RUSAGE_SELF, &usage)
	var rss uint64
	if data, e := os.ReadFile("/proc/self/statm"); e == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			rss = pages * uint64(os.Getpagesize())
		}
	}
	var floor, pruned int64
	var usageDB = (*sql.DB)(nil)
	var storageStateKnown bool
	if r.disk != nil {
		usageDB = r.disk.r.DB
		work, stop := context.WithTimeout(parent, 300*time.Millisecond)
		storageStateKnown = r.disk.r.DB.QueryRowContext(work, "SELECT floor,evicted FROM net_storage WHERE id=1").Scan(&floor, &pruned) == nil
		stop()
	}
	work, stop := context.WithTimeout(parent, 300*time.Millisecond)
	storageUsage := sampleStorageUsage(work, r.cfg, usageDB)
	stop()
	r.healthMu.Lock()
	if storageStateKnown {
		r.health.StorageFloor, r.health.PrunedObservations = floor, pruned
	}
	r.health.Storage = storageUsage
	r.health.Updated = now
	r.health.CPUSeconds = float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	r.health.RSSBytes = rss
	r.health.Counted = uint64(max(int64(0), localTotals.Packets))
	r.health.Received = r.received.Load()
	r.health.MalformedPackets = r.malformed.Load()
	r.health.DeliveryAcks = r.acks.Load()
	r.health.ActivityEntries = int(r.collector.count.Load())
	r.health.ActivityLimit = r.collector.limit
	r.health.ActivityEvictions = r.collector.evictions.Load()
	if last := r.lastPacket.Load(); last != 0 {
		r.health.LastRequest = time.Unix(last, 0)
	}
	r.healthMu.Unlock()
}
func (r *Runtime) Snapshot(_ context.Context, req live.Request) live.Response {
	value := r.report.Load()
	kind := req.Sort
	if kind == "" {
		kind = "score"
	}
	rows := value.rows[kind]
	total := value.totals[kind]
	if req.Local {
		rows = value.local[kind]
		total = value.localTotals
	}
	if req.Op == "show" {
		found := []observation.IP{}
		for _, row := range rows {
			if row.IP == req.IP {
				found = append(found, row)
				break
			}
		}
		rows = found
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	r.healthMu.Lock()
	health := r.health
	r.healthMu.Unlock()
	health.BuildVersion = r.cfg.BuildVersion
	health.Update = r.transport.updateStatus()
	count, bytes := r.queue.size()
	health.PendingIPs = count
	health.QueueBytes = bytes
	health.QueueLimit = r.queue.limit
	health.QueueRejected = r.queue.rejected.Load()
	health.DiscardedSamples = r.queue.discarded.Load()
	peers := r.transport.list()
	nodes, evictions := r.transport.presence.snapshot(peers, time.Now(), r.transport.contactTTL(), true)
	health.NodeCacheEvictions = evictions
	health.ClusterPeers = len(nodes)
	for _, node := range nodes {
		if node.Online {
			health.ClusterOnline++
		}
	}
	for _, p := range peers {
		if p.Success > health.ClusterLastSync.Unix() {
			health.ClusterLastSync = time.Unix(p.Success, 0)
		}
	}
	return live.Response{UpdateOffer: r.transport.updates.snapshot(), Network: true, NetworkNodes: nodes, NetworkIPs: rows, NetworkTotals: total, Health: health, Source: "live", Sort: kind, SnapshotAt: value.at, Cluster: r.cfg.Cluster.Enabled && r.disk != nil && !req.Local, Partial: r.disk == nil || req.Local}
}
func (r *Runtime) close() {
	if r.cancel != nil {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			n, _ := r.queue.size()
			if n == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		r.cancel()
		r.transport.close()
		r.wg.Wait()
	}
	r.transport.close()
	if r.disk != nil {
		r.disk.Close()
	}
	if n, _ := r.queue.size(); n > 0 {
		log.Printf("WARNING: network node stopped with %d unconfirmed RAM observations", n)
	}
}
func Run(ctx context.Context, c config.Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if e := os.MkdirAll(c.Network.RuntimeDirectory, 0750); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(c.Network.RuntimeDirectory, "monitor.lock"), os.O_CREATE|os.O_RDWR, 0640)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("another monitor holds this runtime directory")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	runtime, e := newRuntime(c)
	if e != nil {
		return e
	}
	defer func() { runtime.collector.flush(); runtime.close() }()
	var sock *capture.Socket
	if c.Network.Capture {
		sock, e = capture.OpenNetwork(c.Interface, c.SocketBufferMB)
		if e != nil {
			return e
		}
		defer sock.Close()
		runtime.socket = sock
		runtime.health.ActualBuffer = sock.BufferBytes
		runtime.health.CaptureMode = "tpacket_v3"
	}
	runtime.start()
	server, e := live.Serve(RuntimeBase(c), runtime.Snapshot)
	if e != nil {
		return e
	}
	defer server.Close()
	log.Printf("network monitor role=%s capture=%t interface=%s node=%s", c.Storage.Mode, c.Network.Capture, c.Interface, runtime.transport.node)
	if !c.Network.Capture {
		<-ctx.Done()
		return nil
	}
	nextFlush := time.Now().Add(c.FlushInterval)
	nextStats := time.Now()
	excludes := runtime.transport.excludePorts()
	watch := map[uint16]bool{}
	for _, p := range c.Network.Ports {
		watch[p] = true
	}
	configuredExclude := map[uint16]bool{}
	for _, p := range c.Network.ExcludePorts {
		configuredExclude[p] = true
	}
	var destination netip.Addr
	if c.Destination != "" {
		destination, _ = netip.ParseAddr(c.Destination)
		destination = destination.Unmap()
	}
	for {
		if ctx.Err() != nil {
			runtime.collector.flush()
			return nil
		}
		data, at, e := sock.Next()
		if e != nil {
			return e
		}
		now := time.Now()
		if len(data) > 0 {
			runtime.received.Add(1)
			p, e := observation.Decode(data)
			if e != nil {
				runtime.malformed.Add(1)
			} else if (!destination.IsValid() || p.Destination == destination) && (len(watch) == 0 || watch[p.Port]) && !configuredExclude[p.Port] && !(p.Protocol == 6 && (excludes[p.Port] || excludes[p.SourcePort])) {
				runtime.collector.add(p, at)
				runtime.lastPacket.Store(at.Unix())
			}
		}
		if !now.Before(nextFlush) {
			runtime.collector.flush()
			nextFlush = now.Add(c.FlushInterval)
		}
		if !now.Before(nextStats) {
			drops, e := sock.Drops()
			runtime.healthMu.Lock()
			runtime.health.CaptureUpdated = now
			runtime.health.KernelDrops += uint64(drops)
			runtime.healthMu.Unlock()
			if e != nil {
				return fmt.Errorf("packet statistics: %w", e)
			}
			excludes = runtime.transport.excludePorts()
			nextStats = now.Add(time.Second)
		}
	}
}
