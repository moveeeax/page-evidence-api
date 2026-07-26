// Package evidence defines the on-disk shape of a page-evidence bundle:
// the capture metadata recorded by the renderer, and the manifest that seals
// every artefact with a SHA-256 digest.
//
// The trust chain is deliberately short and auditable:
//
//	artefact bytes -> sha256 -> manifest.json -> sha256 -> RFC 3161 token
//
// Nothing else is signed. A verifier only needs the bundle and the token.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	// ManifestSchema is the value of the manifest "schema" field. It is
	// versioned so that a verifier can refuse a bundle it does not understand.
	ManifestSchema = "page-evidence/manifest/v1"

	// ManifestName is the reserved manifest filename inside a bundle.
	ManifestName = "manifest.json"
	// TokenName is the reserved RFC 3161 TimeStampResp filename inside a bundle.
	TokenName = "timestamp.tsr"
	// CaptureName is the conventional name of the renderer metadata file.
	// Unlike the two names above it is not reserved: it is hashed and listed
	// in the manifest like any other artefact.
	CaptureName = "capture.json"

	// HashAlgorithm is the only digest algorithm v1 bundles use.
	HashAlgorithm = "sha256"
)

// Reserved reports whether name is a bundle control file that is not itself
// listed in the manifest (the manifest cannot hash itself, and the timestamp
// is taken over the manifest so it necessarily comes after it).
func Reserved(name string) bool {
	return name == ManifestName || name == TokenName
}

// Manifest is the sealed inventory of a bundle.
type Manifest struct {
	Schema        string     `json:"schema"`
	BundleID      string     `json:"bundle_id"`
	SealedAt      time.Time  `json:"sealed_at"`
	HashAlgorithm string     `json:"hash_algorithm"`
	Capture       Capture    `json:"capture"`
	Artifacts     []Artifact `json:"artifacts"`
}

// Artifact is one sealed file inside the bundle.
type Artifact struct {
	Path      string `json:"path"`
	Role      string `json:"role"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

// Capture is what the renderer observed. It is embedded in the manifest so
// that the metadata is covered by the timestamp, not just the pixels.
type Capture struct {
	RequestedURL    string              `json:"requested_url"`
	FinalURL        string              `json:"final_url"`
	RedirectChain   []Redirect          `json:"redirect_chain"`
	HTTPStatus      int                 `json:"http_status"`
	RemoteIP        string              `json:"remote_ip"`
	UserAgent       string              `json:"user_agent"`
	Viewport        Viewport            `json:"viewport"`
	FullPage        bool                `json:"full_page"`
	ResponseHeaders map[string][]string `json:"response_headers"`
	StartedAt       time.Time           `json:"started_at"`
	FinishedAt      time.Time           `json:"finished_at"`
	Renderer        Renderer            `json:"renderer"`
}

// Redirect is one hop of the redirect chain that led to the final URL.
type Redirect struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location"`
}

// Viewport is the emulated browser window the capture was taken in.
type Viewport struct {
	Width       int     `json:"width"`
	Height      int     `json:"height"`
	DeviceScale float64 `json:"device_scale"`
}

// Renderer identifies the browser build that produced the artefacts.
type Renderer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Validate rejects capture metadata that is not usable as evidence. A bundle
// whose provenance fields are empty is worse than no bundle: it looks sealed
// but says nothing about what was fetched.
func (c Capture) Validate() error {
	if err := validateHTTPURL("requested_url", c.RequestedURL); err != nil {
		return err
	}
	if err := validateHTTPURL("final_url", c.FinalURL); err != nil {
		return err
	}
	if c.HTTPStatus < 100 || c.HTTPStatus > 599 {
		return fmt.Errorf("capture: http_status %d is not a valid status code", c.HTTPStatus)
	}
	if strings.TrimSpace(c.UserAgent) == "" {
		return fmt.Errorf("capture: user_agent is empty")
	}
	if strings.TrimSpace(c.Renderer.Name) == "" || strings.TrimSpace(c.Renderer.Version) == "" {
		return fmt.Errorf("capture: renderer name and version are required")
	}
	if c.Viewport.Width <= 0 || c.Viewport.Height <= 0 {
		return fmt.Errorf("capture: viewport must have positive width and height")
	}
	if c.Viewport.DeviceScale <= 0 {
		return fmt.Errorf("capture: viewport device_scale must be positive")
	}
	if c.StartedAt.IsZero() || c.FinishedAt.IsZero() {
		return fmt.Errorf("capture: started_at and finished_at are required")
	}
	if c.FinishedAt.Before(c.StartedAt) {
		return fmt.Errorf("capture: finished_at %s precedes started_at %s",
			c.FinishedAt.UTC().Format(time.RFC3339), c.StartedAt.UTC().Format(time.RFC3339))
	}
	for i, r := range c.RedirectChain {
		if err := validateHTTPURL(fmt.Sprintf("redirect_chain[%d].url", i), r.URL); err != nil {
			return err
		}
		if r.Status < 300 || r.Status > 399 {
			return fmt.Errorf("capture: redirect_chain[%d].status %d is not a redirect status", i, r.Status)
		}
	}
	return nil
}

func validateHTTPURL(field, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("capture: %s is empty", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("capture: %s is not a URL: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("capture: %s has scheme %q, want http or https", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("capture: %s has no host", field)
	}
	return nil
}

// Validate checks manifest-level invariants that do not require reading the
// artefact bytes.
func (m *Manifest) Validate() error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("manifest: unsupported schema %q, want %q", m.Schema, ManifestSchema)
	}
	if m.HashAlgorithm != HashAlgorithm {
		return fmt.Errorf("manifest: unsupported hash_algorithm %q, want %q", m.HashAlgorithm, HashAlgorithm)
	}
	if strings.TrimSpace(m.BundleID) == "" {
		return fmt.Errorf("manifest: bundle_id is empty")
	}
	if m.SealedAt.IsZero() {
		return fmt.Errorf("manifest: sealed_at is empty")
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("manifest: no artifacts listed")
	}
	seen := make(map[string]bool, len(m.Artifacts))
	for _, a := range m.Artifacts {
		switch {
		case a.Path == "":
			return fmt.Errorf("manifest: artifact with empty path")
		case Reserved(a.Path):
			return fmt.Errorf("manifest: %s is a reserved name and cannot be listed as an artifact", a.Path)
		case seen[a.Path]:
			return fmt.Errorf("manifest: artifact %q listed twice", a.Path)
		case a.Size < 0:
			return fmt.Errorf("manifest: artifact %q has negative size", a.Path)
		}
		if len(a.SHA256) != 64 {
			return fmt.Errorf("manifest: artifact %q has a malformed sha256 %q", a.Path, a.SHA256)
		}
		if _, err := hex.DecodeString(a.SHA256); err != nil {
			return fmt.Errorf("manifest: artifact %q has a non-hex sha256", a.Path)
		}
		seen[a.Path] = true
	}
	return m.Capture.Validate()
}

// Find returns the manifest entry for path.
func (m *Manifest) Find(path string) (Artifact, bool) {
	for _, a := range m.Artifacts {
		if a.Path == path {
			return a, true
		}
	}
	return Artifact{}, false
}

// Encode renders the manifest as the exact bytes that get written to
// manifest.json and hashed. Indentation and the trailing newline are part of
// the sealed bytes; a verifier never re-serialises the manifest, it hashes the
// file as stored, so formatting can never invalidate a timestamp.
func (m *Manifest) Encode() ([]byte, error) {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return append(buf, '\n'), nil
}

// ParseManifest decodes manifest.json bytes. Unknown fields are rejected: a
// manifest carrying fields this verifier does not understand may be relying on
// them for meaning, and silently ignoring them would overstate what was checked.
func ParseManifest(data []byte) (*Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// ParseCapture decodes renderer metadata.
func ParseCapture(data []byte) (*Capture, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var c Capture
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse capture metadata: %w", err)
	}
	return &c, nil
}

// DigestReader returns the lowercase hex SHA-256 of r along with the number of
// bytes read.
func DigestReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Digest returns the lowercase hex SHA-256 of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
