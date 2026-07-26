// Package bundle opens an evidence bundle from either a directory or a zip
// archive and exposes it as a read-only fs.FS, so every downstream consumer
// (sealer, verifier, exporter) works the same way on both shapes.
package bundle

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Bundle is an opened evidence bundle.
type Bundle struct {
	FS     fs.FS
	Path   string
	IsZip  bool
	closer io.Closer
}

// Close releases the underlying archive handle, if any.
func (b *Bundle) Close() error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

// Open opens a bundle at path. A directory is used as-is; a regular file is
// treated as a zip archive. A zip whose entries all sit under a single top
// level directory is transparently rooted at that directory, so bundles zipped
// with or without a wrapping folder both verify.
func Open(path string) (*Bundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return &Bundle{FS: os.DirFS(path), Path: path}, nil
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open %s as a zip bundle: %w", path, err)
	}
	var fsys fs.FS = zr
	if root, ok := singleRoot(zr); ok {
		sub, err := fs.Sub(zr, root)
		if err != nil {
			zr.Close()
			return nil, err
		}
		fsys = sub
	}
	return &Bundle{FS: fsys, Path: path, IsZip: true, closer: zr}, nil
}

// singleRoot reports the common top level directory of the archive, if every
// entry shares one and the manifest is not already at the archive root.
func singleRoot(zr *zip.ReadCloser) (string, bool) {
	root := ""
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, "./")
		if name == "" {
			continue
		}
		first, _, hasSlash := strings.Cut(name, "/")
		if !hasSlash {
			return "", false // a file sits at the archive root
		}
		if root == "" {
			root = first
		} else if root != first {
			return "", false
		}
	}
	if root == "" {
		return "", false
	}
	return root, true
}

// List returns every regular file in the bundle as slash-separated paths,
// sorted, including reserved control files.
func List(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// ReadFile reads one bundle member.
func ReadFile(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Exists reports whether name is present in the bundle.
func Exists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// fixedModTime is the timestamp stamped on every zip entry. Zip cannot encode
// times before 1980, and a real time here would make archives non-reproducible.
var fixedModTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// Pack writes every file of fsys into a deterministic zip archive at dst.
// Entries are stored in sorted order with a fixed modification time so that
// packing the same bundle twice produces byte-identical archives; that keeps
// the archive digest quotable in a report.
func Pack(fsys fs.FS, dst string) error {
	names, err := List(fsys)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("pack: bundle is empty")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	for _, name := range names {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetMode(0o644)
		hdr.Modified = fixedModTime
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		f, err := fsys.Open(name)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}
