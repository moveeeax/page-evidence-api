package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/moveeeax/page-evidence-api/internal/evidence"
)

// stageCapture builds a capture directory from the fixture artefacts, without
// the manifest or the timestamp, i.e. what the capture worker hands over.
func stageCapture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir("../../testdata/bundles/valid")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if evidence.Reserved(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../testdata/bundles/valid", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSealThenVerify(t *testing.T) {
	dir := stageCapture(t)
	zipPath := filepath.Join(t.TempDir(), "bundle.zip")

	if err := runSeal([]string{dir, "-zip", zipPath}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, evidence.ManifestName)); err != nil {
		t.Fatalf("seal wrote no manifest: %v", err)
	}
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("seal wrote no zip: %v", err)
	}

	// A freshly sealed bundle has no timestamp yet, so it verifies with a
	// warning but must fail under -require-timestamp.
	if err := runVerify([]string{dir}); err != nil {
		t.Errorf("verify of a freshly sealed bundle: %v", err)
	}
	if err := runVerify([]string{dir, "-require-timestamp"}); !errors.Is(err, errVerificationFailed) {
		t.Errorf("verify -require-timestamp = %v, want a verification failure", err)
	}
	if err := runVerify([]string{zipPath}); err != nil {
		t.Errorf("verify of the packed zip: %v", err)
	}
}

func TestVerifyFixturesThroughCLI(t *testing.T) {
	if err := runVerify([]string{"../../testdata/bundles/valid",
		"-tsa-roots", "../../testdata/tsa-test-root.pem", "-require-timestamp"}); err != nil {
		t.Errorf("verify valid fixture: %v", err)
	}
	err := runVerify([]string{"../../testdata/bundles/tampered"})
	if !errors.Is(err, errVerificationFailed) {
		t.Errorf("verify tampered fixture = %v, want a verification failure", err)
	}
}

func TestInspectReadsAFixture(t *testing.T) {
	if err := runInspect([]string{"../../testdata/bundles/valid"}); err != nil {
		t.Errorf("inspect: %v", err)
	}
}

func TestSealRejectsMissingCaptureMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dom.html"), []byte("<p>x</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runSeal([]string{dir}); err == nil {
		t.Fatal("seal accepted a directory with no capture metadata")
	}
}

func TestLoadRootsRejectsNonPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRoots(path); err == nil {
		t.Fatal("loadRoots accepted a file with no certificates")
	}
}
