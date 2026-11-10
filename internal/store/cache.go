package store

import (
	"container/list"
	"net/netip"
	"sync"
)

// The writer cache only contains confirmed rows. Capacity is independent of the
// number of clients on disk; pending targets never enter it before acknowledgement.
type cachedClient struct {
	ip     netip.Addr
	client Client
}
type clientCache struct {
	mu           sync.Mutex
	limit        int
	items        map[netip.Addr]*list.Element
	order        *list.List
	hits, misses uint64
}

func newCache(limit int) *clientCache {
	return &clientCache{limit: limit, items: make(map[netip.Addr]*list.Element), order: list.New()}
}
func (c *clientCache) get(ip netip.Addr) (Client, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.items[ip]; e != nil {
		c.hits++
		c.order.MoveToBack(e)
		return e.Value.(cachedClient).client, true
	}
	c.misses++
	return Client{}, false
}
func (c *clientCache) put(ip netip.Addr, row Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limit == 0 {
		return
	}
	if e := c.items[ip]; e != nil {
		e.Value = cachedClient{ip, row}
		c.order.MoveToBack(e)
		return
	}
	if len(c.items) >= c.limit {
		e := c.order.Front()
		delete(c.items, e.Value.(cachedClient).ip)
		c.order.Remove(e)
	}
	c.items[ip] = c.order.PushBack(cachedClient{ip, row})
}

type CacheStats struct {
	Entries, Limit int
	Hits, Misses   uint64
}

func (s *Store) CacheStats() CacheStats {
	c := s.cache
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{len(c.items), c.limit, c.hits, c.misses}
}

// ConfigureCache must be called before the store is used by a writer.
func (s *Store) ConfigureCache(limit int) { s.cache = newCache(limit) }
