package verify_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moveeeax/page-evidence-api/internal/bundle"
	"github.com/moveeeax/page-evidence-api/internal/evidence"
	"github.com/moveeeax/page-evidence-api/internal/verify"
)

const (
	validFixture    = "../../testdata/bundles/valid"
	tamperedFixture = "../../testdata/bundles/tampered"
	tsaRootFixture  = "../../testdata/tsa-test-root.pem"
)

func testRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	raw, err := os.ReadFile(tsaRootFixture)
	if err != nil {
		t.Fatalf("read TSA root fixture: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("TSA root fixture is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse TSA root fixture: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// copyFixture clones a fixture bundle into a temp dir so a test can damage it.
func copyFixture(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func verifyDir(t *testing.T, dir string, opts verify.Options) *verify.Report {
	t.Helper()
	b, err := bundle.Open(dir)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer b.Close()
	rep, err := verify.Bundle(b.FS, dir, opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return rep
}

func checkStatus(t *testing.T, rep *verify.Report, name string) verify.Status {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	t.Fatalf("no check named %q in report", name)
	return ""
}

func TestValidFixturePassesEndToEnd(t *testing.T) {
	rep := verifyDir(t, validFixture, verify.Options{Roots: testRoots(t), RequireTimestamp: true})
	if !rep.OK {
		t.Fatalf("valid fixture failed verification: %+v", rep.Failures())
	}
	if rep.Timestamp == nil {
		t.Fatal("no timestamp in the report")
	}
	if !rep.Timestamp.ChainVerified {
		t.Error("chain not verified even though the fixture root was supplied")
	}
	if got := rep.Timestamp.GenTime.Format("2006-01-02T15:04:05Z"); got != "2026-07-26T12:00:00Z" {
		t.Errorf("asserted time = %s", got)
	}
	if len(rep.Artifacts) != 5 {
		t.Errorf("artefacts = %d, want 5", len(rep.Artifacts))
	}
	if rep.Capture == nil || rep.Capture.RemoteIP != "203.0.113.42" {
		t.Errorf("capture metadata missing from the report")
	}
	for _, c := range rep.Checks {
		if c.Status != verify.Pass {
			t.Errorf("check %q = %s: %s", c.Name, c.Status, c.Detail)
		}
	}
}

func TestTamperedDOMIsCaught(t *testing.T) {
	rep := verifyDir(t, tamperedFixture, verify.Options{Roots: testRoots(t)})
	if rep.OK {
		t.Fatal("a bundle with an edited dom.html passed verification")
	}
	if s := checkStatus(t, rep, "artifact dom.html"); s != verify.Fail {
		t.Errorf("dom.html check = %s, want fail", s)
	}
	// The timestamp still verifies: only the artefact was changed, and that is
	// precisely what the manifest digest is for.
	if s := checkStatus(t, rep, "trusted timestamp"); s != verify.Pass {
		t.Errorf("timestamp check = %s, want pass", s)
	}
	if len(rep.Failures()) != 1 {
		t.Errorf("failures = %d, want exactly 1", len(rep.Failures()))
	}
}

func TestEditedManifestBreaksTheTimestamp(t *testing.T) {
	dir := copyFixture(t, validFixture)
	path := filepath.Join(dir, evidence.ManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Re-seal the tampered DOM into the manifest: artefact hashes now agree
	// again, but the manifest no longer matches what the TSA signed.
	edited := bytes.Replace(raw, []byte(`"remote_ip": "203.0.113.42"`), []byte(`"remote_ip": "198.51.100.7"`), 1)
	if bytes.Equal(raw, edited) {
		t.Fatal("manifest fixture did not contain the expected field")
	}
	if err := os.WriteFile(path, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, verify.Options{Roots: testRoots(t)})
	if rep.OK {
		t.Fatal("an edited manifest passed verification")
	}
	if s := checkStatus(t, rep, "trusted timestamp"); s != verify.Fail {
		t.Errorf("timestamp check = %s, want fail", s)
	}
	if got := rep.Failures()[0].Detail; !strings.Contains(got, "message imprint") {
		t.Errorf("unexpected failure detail: %s", got)
	}
}

func TestUnlistedFileIsCaught(t *testing.T) {
	dir := copyFixture(t, validFixture)
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("added later"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := verifyDir(t, dir, verify.Options{})
	if rep.OK {
		t.Fatal("a bundle with an extra file passed verification")
	}
	if s := checkStatus(t, rep, "no unlisted content"); s != verify.Fail {
		t.Errorf("unlisted content check = %s, want fail", s)
	}
}

func TestMissingArtifactIsCaught(t *testing.T) {
	dir := copyFixture(t, validFixture)
	if err := os.Remove(filepath.Join(dir, "page.pdf")); err != nil {
		t.Fatal(err)
	}
	rep := verifyDir(t, dir, verify.Options{})
	if rep.OK {
		t.Fatal("a bundle missing an artefact passed verification")
	}
	if s := checkStatus(t, rep, "artifact page.pdf"); s != verify.Fail {
		t.Errorf("page.pdf check = %s, want fail", s)
	}
}

func TestMissingTimestampWarnsUnlessRequired(t *testing.T) {
	dir := copyFixture(t, validFixture)
	if err := os.Remove(filepath.Join(dir, evidence.TokenName)); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, verify.Options{})
	if !rep.OK {
		t.Fatalf("an untimestamped bundle should still verify its hashes: %+v", rep.Failures())
	}
	if s := checkStatus(t, rep, "trusted timestamp"); s != verify.Warn {
		t.Errorf("timestamp check = %s, want warn", s)
	}

	strict := verifyDir(t, dir, verify.Options{RequireTimestamp: true})
	if strict.OK {
		t.Error("-require-timestamp accepted a bundle with no token")
	}
}

func TestChainNotCheckedWithoutRoots(t *testing.T) {
	rep := verifyDir(t, validFixture, verify.Options{})
	if !rep.OK {
		t.Fatalf("verification failed without roots: %+v", rep.Failures())
	}
	if s := checkStatus(t, rep, "timestamp authority"); s != verify.Warn {
		t.Errorf("authority check = %s, want warn", s)
	}
	if rep.Timestamp.ChainVerified {
		t.Error("chain reported as verified without a trust anchor")
	}
}

func TestCorruptTimestampTokenIsCaught(t *testing.T) {
	dir := copyFixture(t, validFixture)
	path := filepath.Join(dir, evidence.TokenName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	rep := verifyDir(t, dir, verify.Options{})
	if rep.OK {
		t.Fatal("a corrupt timestamp token passed verification")
	}
	if s := checkStatus(t, rep, "trusted timestamp"); s != verify.Fail {
		t.Errorf("timestamp check = %s, want fail", s)
	}
}

func TestZipBundleVerifiesIdentically(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "bundle.zip")
	if err := bundle.Pack(os.DirFS(validFixture), zipPath); err != nil {
		t.Fatalf("pack: %v", err)
	}
	b, err := bundle.Open(zipPath)
	if err != nil {
		t.Fatalf("open zip bundle: %v", err)
	}
	defer b.Close()
	if !b.IsZip {
		t.Error("zip bundle not detected as a zip")
	}
	rep, err := verify.Bundle(b.FS, zipPath, verify.Options{Roots: testRoots(t), RequireTimestamp: true})
	if err != nil {
		t.Fatalf("verify zip: %v", err)
	}
	if !rep.OK {
		t.Fatalf("zip bundle failed verification: %+v", rep.Failures())
	}
}

func TestReportJSONIsMachineReadable(t *testing.T) {
	rep := verifyDir(t, validFixture, verify.Options{Roots: testRoots(t)})
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
	var decoded struct {
		OK       bool `json:"ok"`
		BundleID string
		Checks   []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
		Timestamp struct {
			ChainVerified bool `json:"chain_verified"`
		} `json:"timestamp"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("report JSON does not parse: %v", err)
	}
	if !decoded.OK || len(decoded.Checks) == 0 || !decoded.Timestamp.ChainVerified {
		t.Errorf("unexpected JSON report: %s", buf.String())
	}
}

func TestReportTextMentionsResult(t *testing.T) {
	rep := verifyDir(t, tamperedFixture, verify.Options{})
	var buf bytes.Buffer
	if err := rep.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "RESULT: FAIL") {
		t.Errorf("text report does not state the result:\n%s", buf.String())
	}
}
