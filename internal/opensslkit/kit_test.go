package opensslkit_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moveeeax/page-evidence-api/internal/bundle"
	"github.com/moveeeax/page-evidence-api/internal/evidence"
	"github.com/moveeeax/page-evidence-api/internal/opensslkit"
)

const (
	validFixture    = "../../testdata/bundles/valid"
	tamperedFixture = "../../testdata/bundles/tampered"
	tsaRootFixture  = "../../testdata/tsa-test-root.pem"
)

// copyFixture clones a fixture bundle into a temp dir so a test can change it.
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

func export(t *testing.T, src string) (*opensslkit.Kit, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "kit")
	kit, err := opensslkit.Export(os.DirFS(src), out)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return kit, out
}

func TestExportWritesBundleAndKitFiles(t *testing.T) {
	kit, out := export(t, validFixture)

	if kit.BundleID != "peb_971adfcae4957b1b4a6abde1" {
		t.Errorf("bundle id = %s", kit.BundleID)
	}
	if got := kit.GenTime.Format("2006-01-02T15:04:05Z"); got != "2026-07-26T12:00:00Z" {
		t.Errorf("gen time = %s", got)
	}
	if len(kit.Files) != 7 {
		t.Errorf("bundle files = %d, want 7: %v", len(kit.Files), kit.Files)
	}

	// Every bundle file is copied byte for byte: openssl hashes manifest.json
	// as stored, so one changed byte would break step 2.
	for _, f := range kit.Files {
		want, err := os.ReadFile(filepath.Join(validFixture, f))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatalf("kit lacks %s: %v", f, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the bundle", f)
		}
	}
	for _, f := range []string{opensslkit.ChecksumsName, opensslkit.UntrustedName, opensslkit.InstructName} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("kit lacks %s: %v", f, err)
		}
	}
}

func TestChecksumsComeFromTheManifest(t *testing.T) {
	_, out := export(t, validFixture)
	raw, err := os.ReadFile(filepath.Join(validFixture, evidence.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	m, err := evidence.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, a := range m.Artifacts {
		want.WriteString(a.SHA256 + "  " + a.Path + "\n")
	}
	got, err := os.ReadFile(filepath.Join(out, opensslkit.ChecksumsName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want.String() {
		t.Errorf("%s =\n%s\nwant\n%s", opensslkit.ChecksumsName, got, want.String())
	}
}

func TestTamperedBundleKeepsTheManifestDigest(t *testing.T) {
	// The kit copies digests from the manifest instead of hashing the files,
	// so the altered dom.html shows up as a mismatch in sha256sum -c.
	_, out := export(t, tamperedFixture)
	sums, err := os.ReadFile(filepath.Join(out, opensslkit.ChecksumsName))
	if err != nil {
		t.Fatal(err)
	}
	dom, err := os.ReadFile(filepath.Join(out, "dom.html"))
	if err != nil {
		t.Fatal(err)
	}
	line := evidence.Digest(dom) + "  dom.html\n"
	if bytes.Contains(sums, []byte(line)) {
		t.Error("checksums list the tampered dom.html digest instead of the sealed one")
	}
}

func TestUntrustedPEMHoldsTheTokenCertificates(t *testing.T) {
	kit, out := export(t, validFixture)
	raw, err := os.ReadFile(filepath.Join(out, opensslkit.UntrustedName))
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	if len(certs) != kit.Certificates || len(certs) != 2 {
		t.Fatalf("certificates = %d (kit says %d), want 2", len(certs), kit.Certificates)
	}
	if certs[0].Subject.CommonName != "page-evidence test TSA" {
		t.Errorf("first certificate = %s, want the TSA signer", certs[0].Subject)
	}
}

func TestInstructionsNameTheCommands(t *testing.T) {
	kit, out := export(t, validFixture)
	raw, err := os.ReadFile(filepath.Join(out, opensslkit.InstructName))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"sha256sum -c artefacts.sha256",
		"openssl ts -verify -data manifest.json -in timestamp.tsr -untrusted tsa-untrusted.pem -CAfile tsa-root.pem",
		"-attime 1785067200",
		kit.ManifestSHA256,
		"CN=page-evidence test TSA root",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%s does not mention %q", opensslkit.InstructName, want)
		}
	}
}

func TestExportFromZip(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "bundle.zip")
	if err := bundle.Pack(os.DirFS(validFixture), zipPath); err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Open(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	kit, err := opensslkit.Export(b.FS, filepath.Join(t.TempDir(), "kit"))
	if err != nil {
		t.Fatalf("export from zip: %v", err)
	}
	if len(kit.Files) != 7 {
		t.Errorf("bundle files = %d, want 7", len(kit.Files))
	}
}

func TestExportRefusals(t *testing.T) {
	t.Run("no timestamp", func(t *testing.T) {
		dir := copyFixture(t, validFixture)
		if err := os.Remove(filepath.Join(dir, evidence.TokenName)); err != nil {
			t.Fatal(err)
		}
		if _, err := opensslkit.Export(os.DirFS(dir), filepath.Join(t.TempDir(), "kit")); err == nil {
			t.Error("exported a bundle without a timestamp")
		}
	})
	t.Run("no manifest", func(t *testing.T) {
		dir := copyFixture(t, validFixture)
		if err := os.Remove(filepath.Join(dir, evidence.ManifestName)); err != nil {
			t.Fatal(err)
		}
		if _, err := opensslkit.Export(os.DirFS(dir), filepath.Join(t.TempDir(), "kit")); err == nil {
			t.Error("exported a bundle without a manifest")
		}
	})
	t.Run("name collision", func(t *testing.T) {
		dir := copyFixture(t, validFixture)
		if err := os.WriteFile(filepath.Join(dir, opensslkit.InstructName), []byte("trust me"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := opensslkit.Export(os.DirFS(dir), filepath.Join(t.TempDir(), "kit")); err == nil {
			t.Error("exported a bundle whose VERIFY.txt would be overwritten")
		}
	})
	t.Run("non-empty output", func(t *testing.T) {
		out := t.TempDir()
		if err := os.WriteFile(filepath.Join(out, "old.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := opensslkit.Export(os.DirFS(validFixture), out); err == nil {
			t.Error("exported into a non-empty directory")
		}
	})
	t.Run("empty output exists", func(t *testing.T) {
		if _, err := opensslkit.Export(os.DirFS(validFixture), t.TempDir()); err != nil {
			t.Errorf("export into an existing empty directory: %v", err)
		}
	})
}

func TestChecksumsRefuseAmbiguousPaths(t *testing.T) {
	for _, p := range []string{`a\b.html`, "a\nb.html", "../x.html", "/abs.html"} {
		m := &evidence.Manifest{Artifacts: []evidence.Artifact{{Path: p, SHA256: strings.Repeat("0", 64)}}}
		if _, err := opensslkit.Checksums(m); err == nil {
			t.Errorf("Checksums accepted path %q", p)
		}
	}
}

// TestKitVerifiesWithStandardTools runs the commands from VERIFY.txt with the
// real sha256sum and openssl when they are installed. CI has both.
func TestKitVerifiesWithStandardTools(t *testing.T) {
	sha, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skip("sha256sum not installed")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	if v, err := exec.Command(openssl, "version").Output(); err != nil || !bytes.HasPrefix(v, []byte("OpenSSL 3")) {
		t.Skipf("openssl is not OpenSSL 3.x: %s", v)
	}
	root, err := filepath.Abs(tsaRootFixture)
	if err != nil {
		t.Fatal(err)
	}

	run := func(dir, name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		outb, err := cmd.CombinedOutput()
		t.Logf("%s %s:\n%s", filepath.Base(name), strings.Join(args, " "), outb)
		return err
	}
	tsVerify := []string{"ts", "-verify", "-data", "manifest.json", "-in", "timestamp.tsr",
		"-untrusted", "tsa-untrusted.pem", "-CAfile", root}

	_, valid := export(t, validFixture)
	if err := run(valid, sha, "-c", opensslkit.ChecksumsName); err != nil {
		t.Errorf("sha256sum -c on the valid kit: %v", err)
	}
	if err := run(valid, openssl, tsVerify...); err != nil {
		t.Errorf("openssl ts -verify on the valid kit: %v", err)
	}

	_, tampered := export(t, tamperedFixture)
	if err := run(tampered, sha, "-c", opensslkit.ChecksumsName); err == nil {
		t.Error("sha256sum -c passed on the tampered kit")
	}

	// One extra byte in the manifest and openssl must refuse the timestamp.
	path := filepath.Join(valid, evidence.ManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(valid, openssl, tsVerify...); err == nil {
		t.Error("openssl ts -verify passed on an edited manifest")
	}
}
