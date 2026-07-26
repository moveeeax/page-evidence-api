// Package verify checks an evidence bundle offline: every artefact against the
// manifest, the manifest against the RFC 3161 timestamp, and the timestamp
// against a trust anchor.
//
// It never reaches the network. A bundle handed to a compliance officer, a
// lawyer or an opposing party must be checkable on a laptop with no accounts,
// years after it was captured.
package verify

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/page-evidence-api/internal/bundle"
	"github.com/moveeeax/page-evidence-api/internal/evidence"
	"github.com/moveeeax/page-evidence-api/internal/rfc3161"
)

// Status is the outcome of a single check.
type Status string

const (
	// Pass means the check was performed and succeeded.
	Pass Status = "pass"
	// Fail means the check was performed and failed. Any fail invalidates the bundle.
	Fail Status = "fail"
	// Warn means the check could not be performed with the inputs given. It
	// never invalidates a bundle, and it is never silently omitted either.
	Warn Status = "warn"
)

// Check is one line of the verification report.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Timestamp is the human-facing summary of a verified RFC 3161 token.
type Timestamp struct {
	GenTime       time.Time `json:"gen_time"`
	Accuracy      string    `json:"accuracy,omitempty"`
	SerialNumber  string    `json:"serial_number"`
	Policy        string    `json:"policy"`
	Authority     string    `json:"authority"`
	Issuer        string    `json:"issuer"`
	Algorithm     string    `json:"signature_algorithm"`
	CertBinding   string    `json:"certificate_binding"`
	ChainVerified bool      `json:"chain_verified"`
}

// Report is the full result of verifying one bundle.
type Report struct {
	Bundle         string              `json:"bundle"`
	BundleID       string              `json:"bundle_id,omitempty"`
	ManifestSHA256 string              `json:"manifest_sha256,omitempty"`
	Capture        *evidence.Capture   `json:"capture,omitempty"`
	Artifacts      []evidence.Artifact `json:"artifacts,omitempty"`
	Timestamp      *Timestamp          `json:"timestamp,omitempty"`
	Checks         []Check             `json:"checks"`
	OK             bool                `json:"ok"`
}

// Options controls how strict verification is.
type Options struct {
	// Roots is the set of trusted timestamping authority roots. Without it the
	// token signature is still checked, but the chain is reported as unverified.
	Roots *x509.CertPool
	// RequireTimestamp turns a missing timestamp.tsr into a failure instead of
	// a warning. Sealed bundles issued by the API always carry one.
	RequireTimestamp bool
}

func (r *Report) add(name string, status Status, format string, args ...any) {
	detail := format
	if len(args) > 0 {
		detail = fmt.Sprintf(format, args...)
	}
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// Failures returns the checks that failed.
func (r *Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == Fail {
			out = append(out, c)
		}
	}
	return out
}

// Bundle verifies an opened bundle and returns a report. A report is returned
// even when the bundle is broken; err is only non-nil if the bundle could not
// be read at all.
func Bundle(fsys fs.FS, name string, opts Options) (*Report, error) {
	rep := &Report{Bundle: name}

	files, err := bundle.List(fsys)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}

	manifestBytes, err := bundle.ReadFile(fsys, evidence.ManifestName)
	if err != nil {
		rep.add("manifest", Fail, "%s could not be read: %v", evidence.ManifestName, err)
		rep.OK = false
		return rep, nil
	}
	rep.ManifestSHA256 = evidence.Digest(manifestBytes)

	m, err := evidence.ParseManifest(manifestBytes)
	if err != nil {
		rep.add("manifest", Fail, "%v", err)
		rep.OK = false
		return rep, nil
	}
	if err := m.Validate(); err != nil {
		rep.add("manifest", Fail, "%v", err)
		rep.OK = false
		return rep, nil
	}
	rep.BundleID = m.BundleID
	rep.Capture = &m.Capture
	rep.Artifacts = m.Artifacts
	rep.add("manifest", Pass, "schema %s, %d artefacts, sealed %s",
		m.Schema, len(m.Artifacts), m.SealedAt.UTC().Format(time.RFC3339))
	rep.add("capture metadata", Pass, "%s -> %s (%d), %d redirect(s), %s",
		m.Capture.RequestedURL, m.Capture.FinalURL, m.Capture.HTTPStatus,
		len(m.Capture.RedirectChain), m.Capture.Renderer.Name+" "+m.Capture.Renderer.Version)

	ok := checkArtifacts(fsys, m, rep)
	if !checkUnlisted(files, m, rep) {
		ok = false
	}
	if !checkTimestamp(fsys, rep.ManifestSHA256, opts, rep) {
		ok = false
	}

	rep.OK = ok
	return rep, nil
}

func checkArtifacts(fsys fs.FS, m *evidence.Manifest, rep *Report) bool {
	ok := true
	for _, a := range m.Artifacts {
		f, err := fsys.Open(a.Path)
		if err != nil {
			rep.add("artifact "+a.Path, Fail, "listed in the manifest but missing from the bundle")
			ok = false
			continue
		}
		digest, size, err := evidence.DigestReader(f)
		f.Close()
		if err != nil {
			rep.add("artifact "+a.Path, Fail, "unreadable: %v", err)
			ok = false
			continue
		}
		switch {
		case size != a.Size:
			rep.add("artifact "+a.Path, Fail, "size is %d bytes, manifest says %d", size, a.Size)
			ok = false
		case !strings.EqualFold(digest, a.SHA256):
			rep.add("artifact "+a.Path, Fail, "sha256 is %s, manifest says %s", digest, a.SHA256)
			ok = false
		default:
			rep.add("artifact "+a.Path, Pass, "%s sha256:%s… (%d bytes)", a.Role, digest[:16], size)
		}
	}
	return ok
}

func checkUnlisted(files []string, m *evidence.Manifest, rep *Report) bool {
	var unlisted []string
	for _, f := range files {
		if evidence.Reserved(f) {
			continue
		}
		if _, found := m.Find(f); !found {
			unlisted = append(unlisted, f)
		}
	}
	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		rep.add("no unlisted content", Fail,
			"%d file(s) present but not covered by the manifest: %s", len(unlisted), strings.Join(unlisted, ", "))
		return false
	}
	rep.add("no unlisted content", Pass, "every file in the bundle is covered by the manifest")
	return true
}

func checkTimestamp(fsys fs.FS, manifestDigestHex string, opts Options, rep *Report) bool {
	tokenBytes, err := bundle.ReadFile(fsys, evidence.TokenName)
	if err != nil {
		if opts.RequireTimestamp {
			rep.add("trusted timestamp", Fail, "%s is missing", evidence.TokenName)
			return false
		}
		rep.add("trusted timestamp", Warn, "%s is missing; the bundle is sealed but not timestamped", evidence.TokenName)
		return true
	}

	resp, err := rfc3161.ParseResponse(tokenBytes)
	if err != nil {
		rep.add("trusted timestamp", Fail, "%v", err)
		return false
	}
	if !resp.Granted() {
		rep.add("trusted timestamp", Fail, "the TSA did not issue a token: %s %s",
			rfc3161.StatusText(resp.Status), strings.Join(resp.StatusString, " "))
		return false
	}
	token, err := rfc3161.ParseToken(resp.TokenDER)
	if err != nil {
		rep.add("trusted timestamp", Fail, "%v", err)
		return false
	}

	digest, err := hex.DecodeString(manifestDigestHex)
	if err != nil {
		rep.add("trusted timestamp", Fail, "manifest digest is not hexadecimal: %v", err)
		return false
	}

	res, err := token.Verify(rfc3161.VerifyOptions{Digest: digest, Roots: opts.Roots})
	if err != nil {
		rep.add("trusted timestamp", Fail, "%v", err)
		return false
	}

	accuracy := ""
	if res.Accuracy > 0 {
		accuracy = "±" + res.Accuracy.String()
	}
	rep.Timestamp = &Timestamp{
		GenTime:       res.GenTime,
		Accuracy:      accuracy,
		SerialNumber:  res.SerialNumber.String(),
		Policy:        res.Policy,
		Authority:     res.SignerSubject,
		Issuer:        res.SignerIssuer,
		Algorithm:     res.SignatureAlgorithm,
		CertBinding:   res.SigningCertAttr,
		ChainVerified: res.ChainVerified,
	}
	rep.add("trusted timestamp", Pass, "manifest sha256 was timestamped at %s by %s",
		res.GenTime.Format(time.RFC3339), res.SignerSubject)

	if res.ChainVerified {
		rep.add("timestamp authority", Pass, "signer chains to a supplied trusted root")
	} else {
		rep.add("timestamp authority", Warn,
			"chain not checked: no TSA roots supplied (pass -tsa-roots to prove who signed it)")
	}
	return true
}

// WriteText renders the report the way an auditor reads it: one line per check.
func (r *Report) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "bundle:   %s\n", r.Bundle)
	if r.BundleID != "" {
		fmt.Fprintf(w, "id:       %s\n", r.BundleID)
	}
	if r.ManifestSHA256 != "" {
		fmt.Fprintf(w, "manifest: sha256:%s\n", r.ManifestSHA256)
	}
	fmt.Fprintln(w)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  [%s] %-28s %s\n", strings.ToUpper(string(c.Status)), c.Name, c.Detail)
	}
	fmt.Fprintln(w)
	if r.OK {
		fmt.Fprintln(w, "RESULT: PASS — every artefact matches the sealed manifest")
	} else {
		fmt.Fprintf(w, "RESULT: FAIL — %d check(s) failed\n", len(r.Failures()))
	}
	return nil
}

// WriteJSON renders the report for machines.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
