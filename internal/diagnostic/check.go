package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/live"
)

type Finding struct{ Level, Message string }

func Checks(c config.Config, startup bool) []Finding {
	var out []Finding
	add := func(level, format string, args ...any) {
		out = append(out, Finding{level, fmt.Sprintf(format, args...)})
	}
	if e := c.Validate(); e != nil {
		add("FAIL", "configuration: %v", e)
		return out
	}
	add("OK", "configuration is valid")
	if c.Cluster.Enabled {
		if _, e := cluster.ReadKey(c.Cluster.KeyFile); e != nil {
			add("FAIL", "cluster key: %v", e)
		} else {
			add("OK", "cluster key is valid; HTTPS/mutual TLS enabled")
		}
		if st, e := os.Stat(c.Cluster.KeyFile); e == nil {
			if known, allowed := serviceAccess(st, 0400); known && !allowed {
				add("FAIL", "service account cannot read cluster key %s", c.Cluster.KeyFile)
			}
		}
		add("OK", "cluster listener %s; shared database %s", c.Cluster.Listen, cluster.Path(c.Database))
	}

	iface, e := net.InterfaceByName(c.Interface)
	if e != nil {
		if errors.Is(e, syscall.EPERM) || errors.Is(e, syscall.EACCES) {
			add("FAIL", "cannot inspect network interfaces: %v", e)
		} else {
			var names []string
			if list, err := net.Interfaces(); err == nil {
				for _, i := range list {
					names = append(names, i.Name)
				}
			}
			add("FAIL", "interface %q does not exist; available: %s", c.Interface, strings.Join(names, ", "))
		}
	} else if iface.Flags&net.FlagUp == 0 {
		add("FAIL", "interface %s is down", c.Interface)
	} else {
		add("OK", "interface %s is up; ingress UDP/TCP port %d", c.Interface, c.Port)
	}
	if len(live.Path(c.Database)) > 107 {
		add("FAIL", "database path is too long for a Unix diagnostic socket")
	}
	add("OK", "TPACKET_V3 receive ring: %d MiB (not capped by net.core.rmem_max)", c.SocketBufferMB)
	dir := filepath.Dir(c.Database)
	if st, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) && startup {
			add("WARN", "database directory %s must be created by the installer/systemd", dir)
		} else {
			add("FAIL", "database directory: %v", err)
		}
	} else if !st.IsDir() {
		add("FAIL", "database parent is not a directory: %s", dir)
	} else {
		add("OK", "database directory exists: %s", dir)
		if known, allowed := serviceAccess(st, 0300); known && !allowed {
			add("FAIL", "service account needs write and search permission on %s (check owner/group)", dir)
		}
		var fs syscall.Statfs_t
		if err := syscall.Statfs(dir, &fs); err == nil {
			free := uint64(fs.Bavail) * uint64(fs.Bsize)
			level := "OK"
			if free < 64<<20 {
				level = "WARN"
			}
			add(level, "available disk space: %.1f MiB; main DB limit: %d MiB", float64(free)/(1<<20), c.MaxDatabaseMB)
		}
	}
	if st, err := os.Stat(c.Database); err == nil {
		level := "OK"
		if st.Size() > c.MaxDatabaseMB<<20 {
			level = "FAIL"
		}
		add(level, "main database size: %.2f MiB", float64(st.Size())/(1<<20))
		if known, allowed := serviceAccess(st, 0600); known && !allowed {
			add("FAIL", "service account needs read/write access to %s", c.Database)
		}
	} else if os.IsNotExist(err) && startup {
		add("OK", "database will be initialized on first start")
	} else if os.IsNotExist(err) {
		add("WARN", "database has not been initialized yet")
	} else {
		add("FAIL", "database: %v", err)
	}
	if !strings.HasPrefix(c.Database, "/var/lib/netmon/") {
		add("WARN", "custom DB path: verify systemd ReadWritePaths and directory ownership")
	}
	if !startup {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if r, err := live.Fetch(ctx, c.Database, live.Request{Op: "health"}); err == nil {
			h := r.Health
			add("OK", "capture process pid=%d; counted=%d; kernel drops=%d", h.PID, h.Counted, h.KernelDrops)
			if h.LastRequest.IsZero() {
				add("WARN", "no DNS request observed since this process started")
			}
			if h.BlockedFor > 0 {
				add("WARN", "capture waiting for storage for %s; oldest pending %s", h.BlockedFor.Round(time.Millisecond), h.PendingAge.Round(time.Millisecond))
			}
			if h.CaptureError != "" {
				add("FAIL", "capture: %s", h.CaptureError)
			}
			if h.FlushError != "" {
				add("FAIL", "writer: %s", h.FlushError)
			}
		} else {
			add("WARN", "live monitor unavailable; inspect journalctl -u netmon")
		}
	}
	return out
}

// Follow POSIX owner/group precedence, including supplementary service groups.
func modeAllows(uid, gid uint32, mode os.FileMode, serviceUID uint32, groups map[uint32]bool, need os.FileMode) bool {
	if uid == serviceUID {
		return mode&need == need
	}
	if groups[gid] {
		return mode&(need>>3) == need>>3
	}
	return mode&(need>>6) == need>>6
}
func serviceAccess(info os.FileInfo, need os.FileMode) (bool, bool) {
	accountName := os.Getenv("NETMON_SERVICE_USER")
	if accountName == "" {
		accountName = "netmon"
	}
	account, e := user.Lookup(accountName)
	if os.Geteuid() != 0 && os.Getenv("NETMON_SERVICE_USER") == "" {
		account, e = user.LookupId(strconv.Itoa(os.Geteuid()))
	}
	if e != nil {
		return false, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	uid, _ := strconv.ParseUint(account.Uid, 10, 32)
	primary, _ := strconv.ParseUint(account.Gid, 10, 32)
	groups := map[uint32]bool{uint32(primary): true}
	if list, e := account.GroupIds(); e == nil {
		for _, g := range list {
			n, e := strconv.ParseUint(g, 10, 32)
			if e == nil {
				groups[uint32(n)] = true
			}
		}
	}
	return true, modeAllows(stat.Uid, stat.Gid, info.Mode().Perm(), uint32(uid), groups, need)
}
