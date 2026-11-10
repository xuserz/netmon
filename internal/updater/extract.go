package updater

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Extract refuses links, path traversal, devices, duplicates and oversized
// archives, even though executable contents must already have a valid signature.
func Extract(archive, dest string) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 256<<20))
	seen := map[string]bool{}
	var total int64
	if e = os.Mkdir(dest, 0700); e != nil {
		return e
	}
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		name := path.Clean(h.Name)
		if count >= 256 || name == "." || name != h.Name || path.IsAbs(name) || strings.Contains(name, "\\") || name == ".." || strings.HasPrefix(name, "../") || seen[name] {
			return errors.New("unsafe update archive entry")
		}
		seen[name] = true
		target := filepath.Join(dest, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(target, 0700); e != nil {
				return e
			}
		case tar.TypeReg:
			total += h.Size
			if h.Size < 0 || h.Size > 64<<20 || total > 192<<20 {
				return errors.New("update archive exceeds extraction limit")
			}
			if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
				return e
			}
			mode := os.FileMode(0600)
			if h.Mode&0111 != 0 {
				mode = 0700
			}
			out, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if e != nil {
				return e
			}
			_, e = io.Copy(out, tr)
			ce := out.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return errors.New("update archive contains a link or special file")
		}
	}
}
