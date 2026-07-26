package bundle_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/moveeeax/page-evidence-api/internal/bundle"
)

func writeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestOpenDirectoryAndList(t *testing.T) {
	dir := writeDir(t, map[string]string{
		"manifest.json": "{}",
		"dom.html":      "<p>x</p>",
		"extra/log.txt": "hello",
	})
	b, err := bundle.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer b.Close()
	if b.IsZip {
		t.Error("directory reported as a zip")
	}
	got, err := bundle.List(b.FS)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dom.html", "extra/log.txt", "manifest.json"}
	if len(got) != len(want) {
		t.Fatalf("list = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("list[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if data, err := bundle.ReadFile(b.FS, "extra/log.txt"); err != nil || string(data) != "hello" {
		t.Errorf("ReadFile = %q, %v", data, err)
	}
	if !bundle.Exists(b.FS, "dom.html") || bundle.Exists(b.FS, "missing.html") {
		t.Error("Exists is wrong")
	}
}

func TestPackRoundTrip(t *testing.T) {
	dir := writeDir(t, map[string]string{
		"manifest.json":  `{"schema":"x"}`,
		"screenshot.png": "pixels",
	})
	out := filepath.Join(t.TempDir(), "bundle.zip")
	if err := bundle.Pack(os.DirFS(dir), out); err != nil {
		t.Fatalf("pack: %v", err)
	}

	b, err := bundle.Open(out)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer b.Close()
	if !b.IsZip {
		t.Error("zip not reported as a zip")
	}
	data, err := bundle.ReadFile(b.FS, "manifest.json")
	if err != nil || string(data) != `{"schema":"x"}` {
		t.Errorf("manifest through zip = %q, %v", data, err)
	}
}

func TestPackIsReproducible(t *testing.T) {
	dir := writeDir(t, map[string]string{"a.txt": "one", "b.txt": "two"})
	tmp := t.TempDir()
	first := filepath.Join(tmp, "1.zip")
	second := filepath.Join(tmp, "2.zip")
	for _, out := range []string{first, second} {
		if err := bundle.Pack(os.DirFS(dir), out); err != nil {
			t.Fatal(err)
		}
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, bb) {
		t.Error("packing the same bundle twice produced different archives")
	}
}

func TestOpenZipWithWrappingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapped.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range map[string]string{
		"peb_123/manifest.json": "{}",
		"peb_123/dom.html":      "<p>x</p>",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	b, err := bundle.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer b.Close()
	if !bundle.Exists(b.FS, "manifest.json") {
		t.Error("a zip wrapped in a single directory was not rooted at that directory")
	}
}

func TestOpenRejectsNonZipFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notazip.bin")
	if err := os.WriteFile(path, []byte("definitely not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open(path); err == nil {
		t.Fatal("open accepted a file that is not a zip")
	}
}

func TestPackRejectsEmptyBundle(t *testing.T) {
	dir := t.TempDir()
	if err := bundle.Pack(os.DirFS(dir), filepath.Join(t.TempDir(), "empty.zip")); err == nil {
		t.Fatal("pack accepted an empty bundle")
	}
}
