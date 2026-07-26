package evidence_test

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/moveeeax/page-evidence-api/internal/evidence"
)

func sampleCapture() evidence.Capture {
	start := time.Date(2026, 7, 26, 11, 0, 0, 0, time.UTC)
	return evidence.Capture{
		RequestedURL: "https://promo.example.com/offer",
		FinalURL:     "https://promo.example.com/offer",
		HTTPStatus:   200,
		RemoteIP:     "203.0.113.9",
		UserAgent:    "HeadlessChrome/126",
		Viewport:     evidence.Viewport{Width: 1280, Height: 800, DeviceScale: 2},
		StartedAt:    start,
		FinishedAt:   start.Add(time.Second),
		Renderer:     evidence.Renderer{Name: "HeadlessChrome", Version: "126.0.6478.126"},
	}
}

func sampleFS() fstest.MapFS {
	return fstest.MapFS{
		"screenshot.png": {Data: []byte("\x89PNG\r\n\x1a\nfake pixels")},
		"dom.html":       {Data: []byte("<!doctype html><p>offer</p>")},
		"page.pdf":       {Data: []byte("%PDF-1.4 fake")},
	}
}

func TestSealHashesEveryFile(t *testing.T) {
	m, err := evidence.Seal(sampleFS(), sampleCapture(), evidence.SealOptions{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(m.Artifacts) != 3 {
		t.Fatalf("artefacts = %d, want 3", len(m.Artifacts))
	}
	if m.Artifacts[0].Path != "dom.html" {
		t.Errorf("artefacts are not sorted: %s first", m.Artifacts[0].Path)
	}

	dom, ok := m.Find("dom.html")
	if !ok {
		t.Fatal("dom.html missing from the manifest")
	}
	want := evidence.Digest([]byte("<!doctype html><p>offer</p>"))
	if dom.SHA256 != want {
		t.Errorf("dom.html sha256 = %s, want %s", dom.SHA256, want)
	}
	if dom.Size != 27 {
		t.Errorf("dom.html size = %d, want 27", dom.Size)
	}
	if dom.Role != "dom" || dom.MediaType != "text/html; charset=utf-8" {
		t.Errorf("dom.html role/type = %s/%s", dom.Role, dom.MediaType)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("sealed manifest does not validate: %v", err)
	}
}

func TestSealSkipsReservedNames(t *testing.T) {
	fsys := sampleFS()
	fsys[evidence.ManifestName] = &fstest.MapFile{Data: []byte("{}")}
	fsys[evidence.TokenName] = &fstest.MapFile{Data: []byte("der")}

	m, err := evidence.Seal(fsys, sampleCapture(), evidence.SealOptions{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for _, a := range m.Artifacts {
		if evidence.Reserved(a.Path) {
			t.Errorf("reserved file %s was sealed as an artefact", a.Path)
		}
	}
	if len(m.Artifacts) != 3 {
		t.Errorf("artefacts = %d, want 3", len(m.Artifacts))
	}
}

func TestSealIsDeterministic(t *testing.T) {
	sealedAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	a, err := evidence.Seal(sampleFS(), sampleCapture(), evidence.SealOptions{SealedAt: sealedAt})
	if err != nil {
		t.Fatal(err)
	}
	b, err := evidence.Seal(sampleFS(), sampleCapture(), evidence.SealOptions{SealedAt: sealedAt})
	if err != nil {
		t.Fatal(err)
	}
	if a.BundleID != b.BundleID {
		t.Errorf("bundle ids differ: %s vs %s", a.BundleID, b.BundleID)
	}
	ea, _ := a.Encode()
	eb, _ := b.Encode()
	if string(ea) != string(eb) {
		t.Error("sealing the same capture twice produced different manifest bytes")
	}
	if !strings.HasPrefix(a.BundleID, "peb_") {
		t.Errorf("bundle id = %q, want a peb_ prefix", a.BundleID)
	}
}

func TestSealRejectsEmptyDirectory(t *testing.T) {
	if _, err := evidence.Seal(fstest.MapFS{}, sampleCapture(), evidence.SealOptions{}); err == nil {
		t.Fatal("seal accepted an empty directory")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m, err := evidence.Seal(sampleFS(), sampleCapture(), evidence.SealOptions{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if encoded[len(encoded)-1] != '\n' {
		t.Error("encoded manifest does not end with a newline")
	}
	back, err := evidence.ParseManifest(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.BundleID != m.BundleID || len(back.Artifacts) != len(m.Artifacts) {
		t.Error("manifest does not round-trip")
	}
	if !back.SealedAt.Equal(m.SealedAt) {
		t.Errorf("sealed_at does not round-trip: %s vs %s", back.SealedAt, m.SealedAt)
	}
	reencoded, err := back.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != string(encoded) {
		t.Error("re-encoding a parsed manifest changed its bytes")
	}
}

func TestParseManifestRejectsUnknownFields(t *testing.T) {
	_, err := evidence.ParseManifest([]byte(`{"schema":"page-evidence/manifest/v1","surprise":true}`))
	if err == nil {
		t.Fatal("parse accepted a manifest with unknown fields")
	}
}

func TestManifestValidateRejectsBadEntries(t *testing.T) {
	base := func() *evidence.Manifest {
		m, err := evidence.Seal(sampleFS(), sampleCapture(), evidence.SealOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	cases := map[string]func(*evidence.Manifest){
		"bad schema":       func(m *evidence.Manifest) { m.Schema = "page-evidence/manifest/v99" },
		"bad hash algo":    func(m *evidence.Manifest) { m.HashAlgorithm = "md5" },
		"empty bundle id":  func(m *evidence.Manifest) { m.BundleID = "" },
		"no artefacts":     func(m *evidence.Manifest) { m.Artifacts = nil },
		"reserved path":    func(m *evidence.Manifest) { m.Artifacts[0].Path = evidence.ManifestName },
		"duplicate path":   func(m *evidence.Manifest) { m.Artifacts[1].Path = m.Artifacts[0].Path },
		"short digest":     func(m *evidence.Manifest) { m.Artifacts[0].SHA256 = "abcd" },
		"non-hex digest":   func(m *evidence.Manifest) { m.Artifacts[0].SHA256 = strings.Repeat("z", 64) },
		"invalid capture":  func(m *evidence.Manifest) { m.Capture.FinalURL = "ftp://example.com/x" },
		"zero sealed time": func(m *evidence.Manifest) { m.SealedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(m)
			if err := m.Validate(); err == nil {
				t.Errorf("Validate accepted a manifest with %s", name)
			}
		})
	}
}

func TestCaptureValidate(t *testing.T) {
	cases := map[string]func(*evidence.Capture){
		"missing requested url": func(c *evidence.Capture) { c.RequestedURL = "" },
		"non-http scheme":       func(c *evidence.Capture) { c.RequestedURL = "file:///etc/passwd" },
		"no host":               func(c *evidence.Capture) { c.FinalURL = "https:///offer" },
		"impossible status":     func(c *evidence.Capture) { c.HTTPStatus = 999 },
		"no user agent":         func(c *evidence.Capture) { c.UserAgent = " " },
		"no renderer":           func(c *evidence.Capture) { c.Renderer = evidence.Renderer{} },
		"zero viewport":         func(c *evidence.Capture) { c.Viewport.Width = 0 },
		"zero device scale":     func(c *evidence.Capture) { c.Viewport.DeviceScale = 0 },
		"time travel":           func(c *evidence.Capture) { c.FinishedAt = c.StartedAt.Add(-time.Minute) },
		"non-redirect hop": func(c *evidence.Capture) {
			c.RedirectChain = []evidence.Redirect{{URL: "https://example.com/", Status: 200}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := sampleCapture()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted a capture with %s", name)
			}
		})
	}

	valid := sampleCapture()
	valid.RedirectChain = []evidence.Redirect{{URL: "http://example.com/", Status: 301, Location: "https://example.com/"}}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate rejected a good capture: %v", err)
	}
}

func TestRoleAndMediaType(t *testing.T) {
	cases := []struct{ path, role, media string }{
		{"screenshot.png", "screenshot", "image/png"},
		{"page.pdf", "pdf", "application/pdf"},
		{"dom.html", "dom", "text/html; charset=utf-8"},
		{"headers.json", "response-headers", "application/json"},
		{"capture.json", "capture-metadata", "application/json"},
		{"console.log", "other", "text/plain; charset=utf-8"},
		{"blob.bin", "other", "application/octet-stream"},
	}
	for _, c := range cases {
		if got := evidence.Role(c.path); got != c.role {
			t.Errorf("Role(%s) = %s, want %s", c.path, got, c.role)
		}
		if got := evidence.MediaType(c.path); got != c.media {
			t.Errorf("MediaType(%s) = %s, want %s", c.path, got, c.media)
		}
	}
}

func TestDigestMatchesKnownVector(t *testing.T) {
	// SHA-256 of the empty string, the standard sanity check.
	if got := evidence.Digest(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Digest(nil) = %s", got)
	}
}
