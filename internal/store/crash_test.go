package store

import (
	"bufio"
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCrashRecoveryHelper(t *testing.T) {
	path := os.Getenv("DNSMON_CRASH_HELPER")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s, e := Open(path, true, 8, 2)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Flush(map[netip.Addr]Delta{netip.MustParseAddr("::1"): {7, 1, 2}}); e != nil {
		t.Fatal(e)
	}
	tx, e := s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec("UPDATE clients SET requests=requests+10000"); e != nil {
		t.Fatal(e)
	}
	os.Stdout.WriteString("READY\n")
	for {
		time.Sleep(time.Hour)
	}
}
func TestSIGKILLPreservesCommittedCountersAndRollsBackUncommittedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashRecoveryHelper$")
	cmd.Env = append(os.Environ(), "DNSMON_CRASH_HELPER="+path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(out).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "READY\n" {
			t.Fatal("helper failed", line, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper timed out")
	}
	if e = cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Wait(); e == nil {
		t.Fatal("expected SIGKILL")
	}
	s, e := Open(path, true, 8, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var integrity string
	if e = s.DB.QueryRow("PRAGMA quick_check").Scan(&integrity); e != nil || integrity != "ok" {
		t.Fatal(integrity, e)
	}
	total, e := s.Totals(context.Background())
	if e != nil || total.Requests != "7" || total.Unique != 1 {
		t.Fatal(total, e)
	}
	if e = s.Flush(map[netip.Addr]Delta{netip.MustParseAddr("::1"): {3, 3, 3}}); e != nil {
		t.Fatal(e)
	}
	total, _ = s.Totals(context.Background())
	if total.Requests != "10" {
		t.Fatal(total)
	}
}
