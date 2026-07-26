package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// SealOptions tunes manifest construction.
type SealOptions struct {
	// SealedAt is the time recorded in the manifest. Zero means time.Now().
	SealedAt time.Time
}

// Seal walks fsys, hashes every non-reserved file and returns the manifest
// that covers them. It does not write anything: the caller decides where the
// manifest bytes land, because those exact bytes are what gets timestamped.
func Seal(fsys fs.FS, capture Capture, opts SealOptions) (*Manifest, error) {
	if err := capture.Validate(); err != nil {
		return nil, err
	}

	var artifacts []Artifact
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("seal: %s is not a regular file", p)
		}
		if Reserved(p) {
			return nil
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		digest, size, err := DigestReader(f)
		if err != nil {
			return fmt.Errorf("seal: hash %s: %w", p, err)
		}
		artifacts = append(artifacts, Artifact{
			Path:      p,
			Role:      Role(p),
			MediaType: MediaType(p),
			Size:      size,
			SHA256:    digest,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(artifacts) == 0 {
		return nil, fmt.Errorf("seal: no artefacts found to seal")
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })

	sealedAt := opts.SealedAt
	if sealedAt.IsZero() {
		sealedAt = time.Now()
	}

	m := &Manifest{
		Schema:        ManifestSchema,
		BundleID:      bundleID(capture, artifacts),
		SealedAt:      sealedAt.UTC().Truncate(time.Second),
		HashAlgorithm: HashAlgorithm,
		Capture:       capture,
		Artifacts:     artifacts,
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// bundleID is derived from the sealed content, so the same capture sealed
// twice yields the same identifier and a duplicate is obvious.
func bundleID(c Capture, artifacts []Artifact) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", c.FinalURL, c.StartedAt.UTC().Format(time.RFC3339Nano))
	for _, a := range artifacts {
		fmt.Fprintf(h, "%s %s\n", a.SHA256, a.Path)
	}
	return "peb_" + hex.EncodeToString(h.Sum(nil))[:24]
}

// Role labels an artefact by the evidentiary purpose it serves. Compliance
// reviewers read the manifest before they read the files.
func Role(p string) string {
	name := strings.ToLower(path.Base(p))
	switch {
	case name == CaptureName:
		return "capture-metadata"
	case name == "headers.json":
		return "response-headers"
	case name == "redirects.json":
		return "redirect-chain"
	case strings.HasSuffix(name, ".png"), strings.HasSuffix(name, ".jpeg"), strings.HasSuffix(name, ".jpg"):
		return "screenshot"
	case strings.HasSuffix(name, ".pdf"):
		return "pdf"
	case strings.HasSuffix(name, ".html"), strings.HasSuffix(name, ".htm"):
		return "dom"
	default:
		return "other"
	}
}

// MediaType maps an artefact path to its IANA media type.
func MediaType(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".pdf":
		return "application/pdf"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".json":
		return "application/json"
	case ".txt", ".log":
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
