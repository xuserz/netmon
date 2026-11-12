package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"netmon/internal/live"
)

func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	_, e := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return e == nil
}

type Options struct {
	Nodes    bool
	Network  bool
	In, Out  *os.File
	Interval time.Duration
	Version  string
	Color    bool
	Sort     string
}
type Fetcher func(ctx context.Context, sort string, nodes bool) (live.Response, error)

func Run(ctx context.Context, opt Options, fetch Fetcher) (err error) {
	if opt.In == nil {
		opt.In = os.Stdin
	}
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if !IsTerminal(opt.In) || !IsTerminal(opt.Out) {
		return errors.New("live top requires an interactive terminal; use --once")
	}
	if opt.Interval < 250*time.Millisecond || opt.Interval > time.Minute {
		return errors.New("refresh interval must be 250ms..1m")
	}
	fd := int(opt.In.Fd())
	original, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return e
	}
	raw := *original
	raw.Lflag &^= unix.ECHO | unix.ICANON
	raw.Iflag &^= unix.ICRNL | unix.IXON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	enter := func() error {
		if e := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); e != nil {
			return e
		}
		_, e := fmt.Fprint(opt.Out, "\x1b[?1049h\x1b[?25l")
		return e
	}
	leave := func() {
		unix.IoctlSetTermios(fd, unix.TCSETS, original)
		fmt.Fprint(opt.Out, "\x1b[0m\x1b[?25h\x1b[?1049l")
	}
	if e = enter(); e != nil {
		leave()
		return e
	}
	defer leave()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGWINCH, syscall.SIGTSTP)
	defer signal.Stop(signals)
	resumed := make(chan os.Signal, 1)
	signal.Notify(resumed, syscall.SIGCONT)
	defer signal.Stop(resumed)
	keys := make(chan byte, 64)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer cancel()
		buf := make([]byte, 64)
		for {
			if ctx.Err() != nil {
				return
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(poll, 100)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			n, err = unix.Read(fd, buf)
			if err != nil || n == 0 {
				return
			}
			for _, key := range buf[:n] {
				select {
				case keys <- key:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	type view struct {
		sort  string
		nodes bool
	}
	type result struct {
		data live.Response
		view view
		err  error
	}
	requests := make(chan view, 1)
	results := make(chan result, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case view := <-requests:
				rctx, stop := context.WithTimeout(ctx, 2*time.Second)
				data, e := fetch(rctx, view.sort, view.nodes)
				stop()
				select {
				case results <- result{data, view, e}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	defer func() { cancel(); workers.Wait() }()
	state := State{Nodes: opt.Nodes, Version: opt.Version, Color: opt.Color, Sort: opt.Sort, Data: live.Response{Network: opt.Network}}
	if state.Sort == "" {
		state.Sort = "total"
	}
	request := func() {
		select {
		case requests <- view{state.Sort, state.Nodes}:
		default:
		}
	}
	size := func() (int, int) {
		w, e := unix.IoctlGetWinsize(int(opt.Out.Fd()), unix.TIOCGWINSZ)
		if e != nil || w.Col == 0 || w.Row == 0 {
			return 80, 24
		}
		return int(w.Col), int(w.Row)
	}
	ticker := time.NewTicker(opt.Interval)
	defer ticker.Stop()
	render := func() error {
		w, h := size()
		visible := max(1, h-11)
		if state.Data.Network {
			visible = state.networkPageRows(h)
		}
		state.Offset = max(0, min(state.Offset, max(0, state.rowCount()-visible)))
		_, e := fmt.Fprint(opt.Out, "\x1b[H", Render(state, w, h))
		return e
	}
	var previous live.Health
	var previousPoll time.Time
	var decoder keyDecoder
	request()
	if e = render(); e != nil {
		return e
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case sig := <-signals:
			if sig == syscall.SIGTSTP {
				// kill(SIGSTOP) can return before the process actually stops. Wait for
				// a separately delivered SIGCONT before re-entering raw/alternate mode.
				select {
				case <-resumed:
				default:
				}
				leave()
				if e = unix.Kill(os.Getpid(), unix.SIGSTOP); e != nil {
					return e
				}
				select {
				case <-resumed:
				case <-ctx.Done():
					return nil
				}
				if e = enter(); e != nil {
					return e
				}
			}
		case <-resumed:
			request()
		case <-ticker.C:
			if !state.Paused {
				request()
			}
		case r := <-results:
			if r.view != (view{state.Sort, state.Nodes}) {
				request()
				continue
			}
			if r.err != nil {
				state.Error = r.err.Error()
			} else if !state.Paused {
				state.Data = r.data
				state.Error = ""
				h := r.data.Health
				now := time.Now()
				dt := now.Sub(previousPoll).Seconds()
				if h.PID == previous.PID && dt > 0 && h.Counted >= previous.Counted {
					state.Rate = float64(h.Counted-previous.Counted) / dt
					if cpuDt := h.Updated.Sub(previous.Updated).Seconds(); cpuDt > 0 && h.CPUSeconds >= previous.CPUSeconds {
						state.CPU = 100 * (h.CPUSeconds - previous.CPUSeconds) / cpuDt
					}
				} else {
					state.CPU = 0
					state.Rate = 0
				}
				previousPoll = now
				previous = h
				state.History = append(state.History, state.Rate)
				if len(state.History) > 60 {
					state.History = state.History[len(state.History)-60:]
				}
			}
		case key := <-keys:
			action := decoder.Feed(key)
			switch action {
			case "quit":
				return nil
			case "pause":
				state.Paused = !state.Paused
				if !state.Paused {
					request()
				}
			case "refresh":
				request()
			case "nodes":
				if state.Data.Network {
					state.Nodes = !state.Nodes
					state.Offset = 0
					request()
				}
			case "sort":
				if state.Data.Network {
					switch state.Sort {
					case "score":
						state.Sort = "total"
					case "total":
						state.Sort = "bytes"
					case "bytes":
						state.Sort = "syn"
					default:
						state.Sort = "score"
					}
					state.Offset = 0
					request()
					break
				}
				switch state.Sort {
				case "total":
					state.Sort = "rate"
				case "rate":
					state.Sort = "minute"
				default:
					state.Sort = "total"
				}
				state.Offset = 0
				request()
			case "color":
				state.Color = !state.Color
			case "down":
				state.Offset = min(max(0, state.rowCount()-1), state.Offset+1)
			case "up":
				state.Offset = max(0, state.Offset-1)
			case "page_down":
				_, h := size()
				step := max(1, h-12)
				if state.Data.Network {
					step = state.networkPageRows(h)
				}
				state.Offset = min(max(0, state.rowCount()-1), state.Offset+step)
			case "page_up":
				_, h := size()
				step := max(1, h-12)
				if state.Data.Network {
					step = state.networkPageRows(h)
				}
				state.Offset = max(0, state.Offset-step)
			case "home":
				state.Offset = 0
			case "end":
				state.Offset = max(0, state.rowCount()-1)
			}
		}
		if e = render(); e != nil {
			return e
		}
	}
}

type keyDecoder struct{ escape string }

func (d *keyDecoder) Feed(b byte) string {
	if d.escape != "" {
		d.escape += string(b)
		switch d.escape {
		case "\x1b[A":
			d.escape = ""
			return "up"
		case "\x1b[B":
			d.escape = ""
			return "down"
		case "\x1b[5~":
			d.escape = ""
			return "page_up"
		case "\x1b[6~":
			d.escape = ""
			return "page_down"
		case "\x1b[H":
			d.escape = ""
			return "home"
		case "\x1b[F":
			d.escape = ""
			return "end"
		}
		if len(d.escape) > 5 || (len(d.escape) == 2 && b != '[') || (len(d.escape) == 3 && b != '5' && b != '6') {
			d.escape = ""
		}
		return ""
	}
	switch b {
	case 27:
		d.escape = "\x1b"
	case 'q', 'Q', 3:
		return "quit"
	case ' ':
		return "pause"
	case 'r', 'R':
		return "refresh"
	case 'c', 'C':
		return "color"
	case 'n', 'N':
		return "nodes"
	case 's', 'S':
		return "sort"
	case 'j':
		return "down"
	case 'k':
		return "up"
	case 'g':
		return "home"
	case 'G':
		return "end"
	}
	return ""
}
