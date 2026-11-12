// Package opensslkit exports an evidence bundle as a directory that can be
// checked with standard tools only: sha256sum for the artefacts and
// `openssl ts -verify` for the timestamp.
//
// A court expert or the opposing side's lawyer is not going to run a Go
// binary they have never seen. They will run openssl. The kit gives them the
// bundle files, the artefact digests in sha256sum format, the certificates the
// timestamp token carries, and the exact commands, so pev itself is never in
// the trust path.
//
// The kit never contains a trust anchor. The TSA root has to be obtained
// independently, from the authority; a root shipped next to the evidence
// would prove nothing.
package opensslkit

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moveeeax/page-evidence-api/internal/bundle"
	"github.com/moveeeax/page-evidence-api/internal/evidence"
	"github.com/moveeeax/page-evidence-api/internal/rfc3161"
)

// Names of the files the kit adds next to the bundle files.
const (
	ChecksumsName = "artefacts.sha256"
	UntrustedName = "tsa-untrusted.pem"
	InstructName  = "VERIFY.txt"
)

// kitFile reports whether name is one of the files the kit adds. A bundle
// that already contains such a file cannot be exported flat without one
// silently replacing the other.
func kitFile(name string) bool {
	return name == ChecksumsName || name == UntrustedName || name == InstructName
}

// Kit describes what Export wrote.
type Kit struct {
	Dir            string
	BundleID       string
	ManifestSHA256 string
	// Files is every bundle file copied into the kit, slash-separated, sorted.
	Files []string
	// Certificates is the number of certificates written to tsa-untrusted.pem.
	Certificates int
	// GenTime and Authority are what the token states. Export does not verify
	// the token; that is the job of the commands in VERIFY.txt.
	GenTime   time.Time
	Authority string
	// TopIssuer is the issuer of the last embedded certificate, i.e. the name
	// of the root the reader has to obtain from the authority.
	TopIssuer string
}

// Export writes the kit for the bundle in fsys into outDir, which must not
// exist or must be empty. The bundle needs a manifest that parses and a
// timestamp token that carries certificates; artefact digests are copied from
// the manifest, not recomputed, so a tampered artefact is exported as is and
// fails `sha256sum -c` in the reader's hands.
func Export(fsys fs.FS, outDir string) (*Kit, error) {
	manifestBytes, err := bundle.ReadFile(fsys, evidence.ManifestName)
	if err != nil {
		return nil, fmt.Errorf("export: read %s: %w", evidence.ManifestName, err)
	}
	m, err := evidence.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}

	tokenBytes, err := bundle.ReadFile(fsys, evidence.TokenName)
	if err != nil {
		return nil, fmt.Errorf("export: read %s: %w (run `pev stamp` first; openssl has nothing to verify without it)", evidence.TokenName, err)
	}
	resp, err := rfc3161.ParseResponse(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	if !resp.Granted() {
		return nil, fmt.Errorf("export: %s holds no token: %s", evidence.TokenName, rfc3161.StatusText(resp.Status))
	}
	token, err := rfc3161.ParseToken(resp.TokenDER)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	genTime, err := token.GenTime()
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}

	checksums, err := Checksums(m)
	if err != nil {
		return nil, err
	}

	files, err := bundle.List(fsys)
	if err != nil {
		return nil, fmt.Errorf("export: read bundle: %w", err)
	}
	for _, f := range files {
		if kitFile(f) {
			return nil, fmt.Errorf("export: the bundle contains %s, which the kit itself writes", f)
		}
	}

	if err := prepareDir(outDir); err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := copyFile(fsys, f, outDir); err != nil {
			return nil, err
		}
	}

	var untrusted []byte
	for _, c := range token.Certificates {
		untrusted = append(untrusted, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}

	kit := &Kit{
		Dir:            outDir,
		BundleID:       m.BundleID,
		ManifestSHA256: evidence.Digest(manifestBytes),
		Files:          files,
		Certificates:   len(token.Certificates),
		GenTime:        genTime.UTC(),
		Authority:      token.Signer.Subject.String(),
		TopIssuer:      token.Certificates[len(token.Certificates)-1].Issuer.String(),
	}

	writes := []struct {
		name string
		data []byte
	}{
		{ChecksumsName, checksums},
		{UntrustedName, untrusted},
		{InstructName, []byte(instructions(kit))},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(outDir, w.name), w.data, 0o644); err != nil {
			return nil, fmt.Errorf("export: write %s: %w", w.name, err)
		}
	}
	return kit, nil
}

// Checksums renders the manifest's artefact digests in the format
// `sha256sum -c` reads: lowercase hex, two spaces, the path. GNU coreutils
// escapes names containing a backslash or a newline with a leading backslash,
// which other implementations (shasum) do not read the same way, so such
// paths are refused instead of being written ambiguously.
func Checksums(m *evidence.Manifest) ([]byte, error) {
	var b strings.Builder
	for _, a := range m.Artifacts {
		if !fs.ValidPath(a.Path) {
			return nil, fmt.Errorf("export: artefact path %q is not a clean relative path", a.Path)
		}
		if strings.ContainsAny(a.Path, "\\\n\r") {
			return nil, fmt.Errorf("export: artefact path %q contains a backslash or line break that sha256sum would misread", a.Path)
		}
		fmt.Fprintf(&b, "%s  %s\n", strings.ToLower(a.SHA256), a.Path)
	}
	return []byte(b.String()), nil
}

// prepareDir creates dir, or accepts it if it exists and is empty. Writing a
// kit over an old one would leave stale files that the reader then checks.
func prepareDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("export: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("export: %w", err)
	case len(entries) > 0:
		return fmt.Errorf("export: %s is not empty; choose a new directory", dir)
	}
	return nil
}

func copyFile(fsys fs.FS, name, outDir string) error {
	dst := filepath.Join(outDir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("export: %w", err)
	}
	src, err := fsys.Open(name)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return fmt.Errorf("export: copy %s: %w", name, err)
	}
	return out.Close()
}

// instructions renders VERIFY.txt. It is written for a reader who has the
// kit, a shell and OpenSSL, and nothing from us.
func instructions(k *Kit) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	p("Independent verification of evidence bundle %s", k.BundleID)
	p("")
	p("This directory can be checked with sha256sum and OpenSSL alone. You do not")
	p("need pev or anything else from the service that produced the bundle.")
	p("")
	p("What the timestamp token states (not yet checked; the steps below check it):")
	p("  manifest sha256:  %s", k.ManifestSHA256)
	p("  time:             %s", k.GenTime.Format(time.RFC3339))
	p("  authority:        %s", k.Authority)
	p("  root to obtain:   %s", k.TopIssuer)
	p("")
	p("Files in this kit")
	p("")
	for _, f := range k.Files {
		p("  %s", f)
	}
	p("  %s   sha256 of every artefact, copied from manifest.json", ChecksumsName)
	p("  %s  certificates embedded in the token (NOT trusted)", UntrustedName)
	p("  %s         this file", InstructName)
	p("")
	p("Any other file is not part of the evidence.")
	p("")
	p("Step 1. Artefacts match the manifest")
	p("")
	p("  sha256sum -c %s", ChecksumsName)
	p("")
	p("  Every line must end in OK. On macOS without coreutils use")
	p("  `shasum -a 256 -c %s`.", ChecksumsName)
	p("")
	p("  %s is derived from manifest.json, so compare the two: every", ChecksumsName)
	p("  \"path\" and \"sha256\" pair in manifest.json must appear in %s,", ChecksumsName)
	p("  and nothing else. With jq installed:")
	p("")
	p("  jq -r '.artifacts[] | \"\\(.sha256)  \\(.path)\"' manifest.json | diff - %s", ChecksumsName)
	p("")
	p("  No output means they agree.")
	p("")
	p("Step 2. The timestamp covers this manifest")
	p("")
	p("  Obtain the root certificate of the timestamp authority yourself, from the")
	p("  authority's website or another channel you trust, and save it as")
	p("  tsa-root.pem. Do not use %s for this: it came with the", UntrustedName)
	p("  evidence and proves nothing about who signed it.")
	p("")
	p("  openssl ts -verify -data manifest.json -in %s -untrusted %s -CAfile tsa-root.pem", evidence.TokenName, UntrustedName)
	p("")
	p("  The output must end in \"Verification: OK\". OpenSSL may warn that the")
	p("  authority's own certificate in %s \"is not a CA cert\"; that is", UntrustedName)
	p("  expected and does not affect the result.")
	p("")
	p("  If the authority's certificate has expired since the timestamp was issued,")
	p("  check the chain at the time the token states instead of today:")
	p("")
	p("  openssl ts -verify -data manifest.json -in %s -untrusted %s -CAfile tsa-root.pem -attime %d", evidence.TokenName, UntrustedName, k.GenTime.Unix())
	p("")
	p("  Use OpenSSL 3.x. LibreSSL 3.3.6, the /usr/bin/openssl of macOS, fails")
	p("  with \"ess signing certificate error\" on tokens that carry the")
	p("  signingCertificateV2 attribute; Homebrew's openssl does not.")
	p("")
	p("What the two steps prove together")
	p("")
	p("  Step 1: no artefact changed after the manifest was written.")
	p("  Step 2: the manifest existed, byte for byte, at the stated time, and the")
	p("  timestamp was signed by the authority whose root you supplied.")
	return b.String()
}
