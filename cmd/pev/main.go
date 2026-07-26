// Command pev seals, timestamps and verifies page-evidence bundles.
//
// The verify path is the important one: it is a single static binary with no
// dependencies and no network access, so anyone who receives a bundle can
// check it themselves without trusting the service that produced it.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/page-evidence-api/internal/bundle"
	"github.com/moveeeax/page-evidence-api/internal/evidence"
	"github.com/moveeeax/page-evidence-api/internal/rfc3161"
	"github.com/moveeeax/page-evidence-api/internal/verify"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `pev — page evidence bundles

Usage:
  pev seal   <dir> [-capture FILE] [-zip OUT.zip]   seal a capture directory into a manifest
  pev stamp  <dir> [-tsa URL]                       add an RFC 3161 timestamp over the manifest
  pev verify <bundle> [-tsa-roots FILE] [-json]     verify a bundle offline (dir or .zip)
  pev inspect <bundle>                              print what a bundle claims, without verifying
  pev version

Exit codes:
  0  verification passed
  1  verification failed
  2  usage or I/O error
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "seal":
		err = runSeal(os.Args[2:])
	case "stamp":
		err = runStamp(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "version":
		fmt.Printf("pev %s\n", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "pev: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, errVerificationFailed) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "pev: %v\n", err)
		os.Exit(2)
	}
}

// parseFlags parses args allowing flags to appear after positional arguments,
// which is what people actually type: `pev verify bundle -json`.
func parseFlags(fset *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fset.Parse(args); err != nil {
			return nil, err
		}
		if fset.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fset.Arg(0))
		args = fset.Args()[1:]
	}
}

var errVerificationFailed = errors.New("verification failed")

func runSeal(args []string) error {
	fset := flag.NewFlagSet("seal", flag.ExitOnError)
	capturePath := fset.String("capture", "", "renderer metadata JSON (default <dir>/capture.json)")
	zipOut := fset.String("zip", "", "also write the sealed bundle to this zip archive")
	rest, err := parseFlags(fset, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("seal: expected exactly one capture directory")
	}
	dir := rest[0]

	metaPath := *capturePath
	if metaPath == "" {
		metaPath = filepath.Join(dir, evidence.CaptureName)
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("seal: read capture metadata: %w", err)
	}
	capture, err := evidence.ParseCapture(raw)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	manifest, err := evidence.Seal(os.DirFS(dir), *capture, evidence.SealOptions{})
	if err != nil {
		return err
	}
	encoded, err := manifest.Encode()
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(dir, evidence.ManifestName)
	if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
		return fmt.Errorf("seal: write manifest: %w", err)
	}

	fmt.Printf("sealed %s\n", dir)
	fmt.Printf("  bundle id:       %s\n", manifest.BundleID)
	fmt.Printf("  artefacts:       %d\n", len(manifest.Artifacts))
	fmt.Printf("  manifest sha256: %s\n", evidence.Digest(encoded))
	fmt.Printf("\nNext: pev stamp %s   (requests an RFC 3161 timestamp over that digest)\n", dir)

	if *zipOut != "" {
		if err := bundle.Pack(os.DirFS(dir), *zipOut); err != nil {
			return fmt.Errorf("seal: pack: %w", err)
		}
		fmt.Printf("wrote %s\n", *zipOut)
	}
	return nil
}

func runStamp(args []string) error {
	fset := flag.NewFlagSet("stamp", flag.ExitOnError)
	tsaURL := fset.String("tsa", rfc3161.DefaultTSA, "RFC 3161 timestamp authority URL")
	timeout := fset.Duration("timeout", 30*time.Second, "TSA request timeout")
	rest, err := parseFlags(fset, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("stamp: expected exactly one sealed bundle directory")
	}
	dir := rest[0]

	manifestBytes, err := os.ReadFile(filepath.Join(dir, evidence.ManifestName))
	if err != nil {
		return fmt.Errorf("stamp: %w (run `pev seal` first)", err)
	}
	digestHex := evidence.Digest(manifestBytes)
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return err
	}

	client := &rfc3161.Client{Timeout: *timeout}
	respDER, nonce, err := client.Stamp(context.Background(), *tsaURL, digest, rfc3161.RequestOptions{})
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}

	// Never write a token we have not verified against our own request.
	resp, err := rfc3161.ParseResponse(respDER)
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}
	token, err := rfc3161.ParseToken(resp.TokenDER)
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}
	res, err := token.Verify(rfc3161.VerifyOptions{Digest: digest, Nonce: nonce})
	if err != nil {
		return fmt.Errorf("stamp: the TSA response did not verify, refusing to store it: %w", err)
	}

	tokenPath := filepath.Join(dir, evidence.TokenName)
	if err := os.WriteFile(tokenPath, respDER, 0o644); err != nil {
		return fmt.Errorf("stamp: write token: %w", err)
	}
	fmt.Printf("timestamped %s\n", dir)
	fmt.Printf("  manifest sha256: %s\n", digestHex)
	fmt.Printf("  asserted time:   %s\n", res.GenTime.Format(time.RFC3339))
	fmt.Printf("  authority:       %s\n", res.SignerSubject)
	fmt.Printf("  token:           %s (%d bytes)\n", tokenPath, len(respDER))
	return nil
}

func runVerify(args []string) error {
	fset := flag.NewFlagSet("verify", flag.ExitOnError)
	rootsPath := fset.String("tsa-roots", "", "PEM file of trusted timestamping authority roots")
	asJSON := fset.Bool("json", false, "emit the report as JSON")
	requireTS := fset.Bool("require-timestamp", false, "treat a missing timestamp as a failure")
	rest, err := parseFlags(fset, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("verify: expected exactly one bundle (directory or .zip)")
	}

	opts := verify.Options{RequireTimestamp: *requireTS}
	if *rootsPath != "" {
		pool, err := loadRoots(*rootsPath)
		if err != nil {
			return err
		}
		opts.Roots = pool
	}

	b, err := bundle.Open(rest[0])
	if err != nil {
		return err
	}
	defer b.Close()

	rep, err := verify.Bundle(b.FS, rest[0], opts)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			return err
		}
	} else if err := rep.WriteText(os.Stdout); err != nil {
		return err
	}
	if !rep.OK {
		return errVerificationFailed
	}
	return nil
}

func runInspect(args []string) error {
	fset := flag.NewFlagSet("inspect", flag.ExitOnError)
	rest, err := parseFlags(fset, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("inspect: expected exactly one bundle (directory or .zip)")
	}
	b, err := bundle.Open(rest[0])
	if err != nil {
		return err
	}
	defer b.Close()

	raw, err := bundle.ReadFile(b.FS, evidence.ManifestName)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	m, err := evidence.ParseManifest(raw)
	if err != nil {
		return err
	}

	fmt.Printf("bundle id:   %s\n", m.BundleID)
	fmt.Printf("sealed at:   %s\n", m.SealedAt.UTC().Format(time.RFC3339))
	fmt.Printf("requested:   %s\n", m.Capture.RequestedURL)
	fmt.Printf("final URL:   %s (HTTP %d)\n", m.Capture.FinalURL, m.Capture.HTTPStatus)
	if m.Capture.RemoteIP != "" {
		fmt.Printf("resolved IP: %s\n", m.Capture.RemoteIP)
	}
	fmt.Printf("renderer:    %s %s\n", m.Capture.Renderer.Name, m.Capture.Renderer.Version)
	fmt.Printf("viewport:    %dx%d @%gx full-page=%t\n",
		m.Capture.Viewport.Width, m.Capture.Viewport.Height, m.Capture.Viewport.DeviceScale, m.Capture.FullPage)

	if len(m.Capture.RedirectChain) > 0 {
		fmt.Println("redirects:")
		for _, r := range m.Capture.RedirectChain {
			fmt.Printf("  %d %s -> %s\n", r.Status, r.URL, r.Location)
		}
	}
	if n := len(m.Capture.ResponseHeaders); n > 0 {
		keys := make([]string, 0, n)
		for k := range m.Capture.ResponseHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("headers:     %s\n", strings.Join(keys, ", "))
	}

	fmt.Println("artefacts:")
	for _, a := range m.Artifacts {
		fmt.Printf("  %-24s %-16s %8d B  sha256:%s\n", a.Path, a.Role, a.Size, a.SHA256)
	}

	if tokenBytes, err := bundle.ReadFile(b.FS, evidence.TokenName); err == nil {
		fmt.Printf("timestamp:   %s (%d bytes) — run `pev verify` to check it\n", evidence.TokenName, len(tokenBytes))
	} else {
		fmt.Printf("timestamp:   none\n")
	}
	return nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read TSA roots: %w", err)
	}
	pool := x509.NewCertPool()
	rest := raw
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse TSA root: %w", err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("read TSA roots: %s contains no PEM certificates", path)
	}
	return pool, nil
}
