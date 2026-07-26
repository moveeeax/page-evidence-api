// Command genfixture regenerates the example bundles under testdata/.
//
// It is a development tool, not part of the product. The bundles it writes are
// signed by a throwaway test authority whose root is committed next to them, so
// the README example and the end-to-end tests run offline and forever.
//
//	go run ./cmd/genfixture
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moveeeax/page-evidence-api/internal/evidence"
	"github.com/moveeeax/page-evidence-api/internal/tsatest"
)

const outDir = "testdata"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "genfixture: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	authority, err := tsatest.New()
	if err != nil {
		return err
	}

	validDir := filepath.Join(outDir, "bundles", "valid")
	tamperedDir := filepath.Join(outDir, "bundles", "tampered")
	for _, d := range []string{validDir, tamperedDir} {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	files, err := artefacts()
	if err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(validDir, name), content, 0o644); err != nil {
			return err
		}
	}

	capture, err := evidence.ParseCapture(files[evidence.CaptureName])
	if err != nil {
		return err
	}
	manifest, err := evidence.Seal(os.DirFS(validDir), *capture,
		evidence.SealOptions{SealedAt: tsatest.ReferenceTime})
	if err != nil {
		return err
	}
	manifestBytes, err := manifest.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(validDir, evidence.ManifestName), manifestBytes, 0o644); err != nil {
		return err
	}

	digest := evidence.Digest(manifestBytes)
	raw, err := hexBytes(digest)
	if err != nil {
		return err
	}
	respDER, err := authority.Stamp(raw, tsatest.StampOptions{GenTime: tsatest.ReferenceTime})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(validDir, evidence.TokenName), respDER, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "tsa-test-root.pem"), authority.RootPEM(), 0o644); err != nil {
		return err
	}

	// The tampered bundle is the same sealed evidence with one word changed in
	// the DOM: the affiliate's payout claim. Everything else is byte identical,
	// which is exactly the case the verifier exists to catch.
	if err := copyTree(validDir, tamperedDir); err != nil {
		return err
	}
	domPath := filepath.Join(tamperedDir, "dom.html")
	dom, err := os.ReadFile(domPath)
	if err != nil {
		return err
	}
	tampered := bytes.Replace(dom, []byte("up to 20% cashback"), []byte("up to 80% cashback"), 1)
	if bytes.Equal(dom, tampered) {
		return fmt.Errorf("tamper target not found in dom.html")
	}
	if err := os.WriteFile(domPath, tampered, 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %s (manifest sha256:%s)\n", validDir, digest)
	fmt.Printf("wrote %s (dom.html altered)\n", tamperedDir)
	fmt.Printf("wrote %s\n", filepath.Join(outDir, "tsa-test-root.pem"))
	return nil
}

func artefacts() (map[string][]byte, error) {
	shot, err := screenshotPNG()
	if err != nil {
		return nil, err
	}

	captured := time.Date(2026, 7, 26, 11, 59, 58, 0, time.UTC)
	capture := evidence.Capture{
		RequestedURL: "http://promo.example.com/summer-cashback",
		FinalURL:     "https://promo.example.net/summer-cashback?aff=1042",
		RedirectChain: []evidence.Redirect{
			{URL: "http://promo.example.com/summer-cashback", Status: 301, Location: "https://promo.example.com/summer-cashback"},
			{URL: "https://promo.example.com/summer-cashback", Status: 302, Location: "https://promo.example.net/summer-cashback?aff=1042"},
		},
		HTTPStatus: 200,
		RemoteIP:   "203.0.113.42",
		UserAgent:  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36",
		Viewport:   evidence.Viewport{Width: 1280, Height: 800, DeviceScale: 2},
		FullPage:   true,
		ResponseHeaders: map[string][]string{
			"Content-Type":  {"text/html; charset=utf-8"},
			"Date":          {"Sun, 26 Jul 2026 11:59:58 GMT"},
			"Server":        {"nginx"},
			"Cache-Control": {"no-store"},
		},
		StartedAt:  captured,
		FinishedAt: captured.Add(2 * time.Second),
		Renderer:   evidence.Renderer{Name: "HeadlessChrome", Version: "126.0.6478.126"},
	}
	captureJSON, err := json.MarshalIndent(capture, "", "  ")
	if err != nil {
		return nil, err
	}

	headers, err := json.MarshalIndent(capture.ResponseHeaders, "", "  ")
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		"screenshot.png":     shot,
		"page.pdf":           samplePDF(),
		"dom.html":           []byte(sampleDOM),
		"headers.json":       append(headers, '\n'),
		evidence.CaptureName: append(captureJSON, '\n'),
	}, nil
}

// screenshotPNG stands in for a real render: a deterministic image, so the
// fixture digests only change when the fixture is deliberately regenerated.
func screenshotPNG() ([]byte, error) {
	const w, h = 320, 200
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{R: uint8(x * 255 / w), G: uint8(y * 255 / h), B: 0x80, A: 0xff}
			if y > 40 && y < 70 && x > 20 && x < 300 {
				c = color.RGBA{R: 0xf5, G: 0xf5, B: 0xf5, A: 0xff}
			}
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const sampleDOM = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Summer cashback — example affiliate landing page</title></head>
<body>
  <h1>Summer cashback</h1>
  <p class="offer">Earn up to 20% cashback on every purchase made through this link.</p>
  <p class="terms">Offer valid 1 June – 31 August 2026. Cashback is credited within 30 days.
     Maximum payout 50 EUR per customer. Not combinable with other promotions.</p>
  <a class="cta" href="https://track.example.net/click?aff=1042">Claim the offer</a>
</body>
</html>
`

// samplePDF is a hand-written, valid single page PDF. The capture worker will
// emit Chrome's PDF export instead; this only has to be a real file with a
// stable digest.
func samplePDF() []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 320 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		"<< /Length 74 >>\nstream\nBT /F1 12 Tf 24 150 Td (Summer cashback - up to 20% cashback) Tj ET\nendstream",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return buf.Bytes()
}

func copyTree(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func hexBytes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v int
		if _, err := fmt.Sscanf(strings.ToLower(s[i:i+2]), "%02x", &v); err != nil {
			return nil, err
		}
		out = append(out, byte(v))
	}
	return out, nil
}
