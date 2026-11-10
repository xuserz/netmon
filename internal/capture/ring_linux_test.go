//go:build linux

package capture

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestRingFrameTimestampAndBorrowedBytes(t *testing.T) {
	memory := make([]byte, 256)
	binary.NativeEndian.PutUint32(memory[4:], 1700000000)
	binary.NativeEndian.PutUint32(memory[8:], 123456789)
	binary.NativeEndian.PutUint32(memory[12:], 32)
	binary.NativeEndian.PutUint32(memory[16:], 32)
	binary.NativeEndian.PutUint16(memory[24:], 80)
	binary.NativeEndian.PutUint16(memory[26:], 80)
	memory[80] = 0x45
	data, at, _, e := decodeFrame(memory, 0, 112, 1)
	if e != nil || len(data) != 32 || at != time.Unix(1700000000, 123456789) {
		t.Fatal(len(data), at, e)
	}
	data[0] = 0x60
	if memory[80] != 0x60 {
		t.Fatal("packet copied")
	}
	for _, change := range []func([]byte){
		func(b []byte) { binary.NativeEndian.PutUint32(b[8:], 1000000000) },
		func(b []byte) { binary.NativeEndian.PutUint32(b[12:], 31) },
		func(b []byte) { binary.NativeEndian.PutUint16(b[26:], 79) },
		func(b []byte) { binary.NativeEndian.PutUint16(b[26:], 250) },
	} {
		bad := append([]byte(nil), memory...)
		change(bad)
		if _, _, _, e = decodeFrame(bad, 0, 112, 1); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	// A chain cannot overlap its previous packet or point beyond its block.
	for _, next := range []uint32{0, 48, 100, 250} {
		binary.NativeEndian.PutUint32(memory, next)
		if _, _, _, e = decodeFrame(memory, 0, 256, 2); e == nil {
			t.Fatal("invalid next offset", next)
		}
	}
	binary.NativeEndian.PutUint32(memory, 128)
	if _, _, next, e := decodeFrame(memory, 0, 256, 2); e != nil || next != 128 {
		t.Fatal(next, e)
	}
}
func FuzzRingFrame(f *testing.F) {
	f.Add(make([]byte, 48), 0, 48, uint32(1))
	valid := make([]byte, 112)
	binary.NativeEndian.PutUint32(valid[12:], 32)
	binary.NativeEndian.PutUint32(valid[16:], 32)
	binary.NativeEndian.PutUint16(valid[24:], 80)
	binary.NativeEndian.PutUint16(valid[26:], 80)
	f.Add(valid, 0, 112, uint32(1))
	f.Fuzz(func(t *testing.T, b []byte, offset, end int, n uint32) { decodeFrame(b, offset, end, n) })
}
