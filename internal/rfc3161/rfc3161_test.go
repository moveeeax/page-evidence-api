package rfc3161_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/page-evidence-api/internal/rfc3161"
	"github.com/moveeeax/page-evidence-api/internal/tsatest"
)

var testAuthority = func() *tsatest.Authority {
	a, err := tsatest.New()
	if err != nil {
		panic(err)
	}
	return a
}()

func digestOf(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func stamp(t *testing.T, digest []byte, opts tsatest.StampOptions) *rfc3161.Token {
	t.Helper()
	respDER, err := testAuthority.Stamp(digest, opts)
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	resp, err := rfc3161.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !resp.Granted() {
		t.Fatalf("response not granted: %s", rfc3161.StatusText(resp.Status))
	}
	tok, err := rfc3161.ParseToken(resp.TokenDER)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return tok
}

func TestVerifyValidToken(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{})

	res, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest, Roots: testAuthority.RootPool()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.GenTime.Equal(tsatest.ReferenceTime) {
		t.Errorf("genTime = %s, want %s", res.GenTime, tsatest.ReferenceTime)
	}
	if !res.ChainVerified {
		t.Error("chain not verified even though roots were supplied")
	}
	if res.Accuracy != time.Second {
		t.Errorf("accuracy = %s, want 1s", res.Accuracy)
	}
	if res.SignatureAlgorithm != "SHA256-RSA" {
		t.Errorf("signature algorithm = %q", res.SignatureAlgorithm)
	}
	if !strings.HasPrefix(res.SigningCertAttr, "signingCertificateV2") {
		t.Errorf("signing cert attribute = %q", res.SigningCertAttr)
	}
	if res.Policy != "1.3.6.1.4.1.99999.1.1" {
		t.Errorf("policy = %q", res.Policy)
	}
	if got := res.Imprint.HashedMessage; string(got) != string(digest) {
		t.Errorf("imprint does not round-trip")
	}
	if h, err := res.Imprint.Hash(); err != nil || h.Size() != sha256.Size {
		t.Errorf("imprint hash = %v, %v", h, err)
	}
}

func TestVerifyWithoutRootsSkipsChain(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{})

	res, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.ChainVerified {
		t.Error("chain reported as verified without a trust anchor")
	}
}

func TestVerifyRejectsUntrustedRoot(t *testing.T) {
	other, err := tsatest.New()
	if err != nil {
		t.Fatal(err)
	}
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{})

	if _, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest, Roots: other.RootPool()}); err == nil {
		t.Fatal("verify accepted a token signed under a different authority")
	} else if !strings.Contains(err.Error(), "chain") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRejectsWrongDigest(t *testing.T) {
	tok := stamp(t, digestOf("manifest bytes"), tsatest.StampOptions{})

	_, err := tok.Verify(rfc3161.VerifyOptions{Digest: digestOf("tampered manifest"), Roots: testAuthority.RootPool()})
	if err == nil {
		t.Fatal("verify accepted a token for a different digest")
	}
	if !strings.Contains(err.Error(), "message imprint") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRejectsCorruptSignature(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{CorruptSignature: true})

	_, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest})
	if err == nil {
		t.Fatal("verify accepted a corrupt signature")
	}
	if !strings.Contains(err.Error(), "signature does not verify") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRejectsAttrDigestNotCoveringTSTInfo(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{WrongAttrDigest: true})

	_, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest})
	if err == nil {
		t.Fatal("verify accepted signed attributes that do not cover the TSTInfo")
	}
	if !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRejectsMissingSigningCertAttribute(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{OmitSigningCertAttr: true})

	_, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest})
	if err == nil {
		t.Fatal("verify accepted a token with no signingCertificate attribute")
	}
	if !strings.Contains(err.Error(), "signingCertificate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRejectsNonceMismatch(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{Nonce: big.NewInt(4242)})

	if _, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest, Nonce: big.NewInt(4242)}); err != nil {
		t.Fatalf("verify with matching nonce: %v", err)
	}
	_, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest, Nonce: big.NewInt(9999)})
	if err == nil {
		t.Fatal("verify accepted a mismatched nonce")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyRejectsGenTimeOutsideCertValidity(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{GenTime: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)})

	_, err := tok.Verify(rfc3161.VerifyOptions{Digest: digest})
	if err == nil {
		t.Fatal("verify accepted a token dated before the signer certificate existed")
	}
	if !strings.Contains(err.Error(), "validity") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseResponseRejection(t *testing.T) {
	respDER, err := testAuthority.Stamp(digestOf("x"), tsatest.StampOptions{Status: rfc3161.StatusRejection})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rfc3161.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Granted() {
		t.Error("a rejected response reported as granted")
	}
	if rfc3161.StatusText(resp.Status) != "rejected" {
		t.Errorf("status text = %q", rfc3161.StatusText(resp.Status))
	}
}

func TestBuildRequest(t *testing.T) {
	digest := digestOf("manifest bytes")
	der, nonce, err := rfc3161.BuildRequest(digest, rfc3161.RequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if nonce == nil || nonce.Sign() == 0 {
		t.Fatalf("nonce = %v, want a random non-zero value", nonce)
	}

	var req struct {
		Version        int
		MessageImprint struct {
			HashAlgorithm struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			HashedMessage []byte
		}
		ReqPolicy asn1.ObjectIdentifier `asn1:"optional"`
		Nonce     *big.Int              `asn1:"optional"`
		CertReq   bool                  `asn1:"optional,default:false"`
	}
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		t.Fatalf("re-parse request: %v", err)
	}
	if req.Version != 1 {
		t.Errorf("version = %d, want 1", req.Version)
	}
	if !req.CertReq {
		t.Error("certReq is false; the token would not be verifiable offline")
	}
	if req.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce in request = %v, want %v", req.Nonce, nonce)
	}
	if string(req.MessageImprint.HashedMessage) != string(digest) {
		t.Error("message imprint does not match the digest")
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
		t.Errorf("hash algorithm = %v, want SHA-256", req.MessageImprint.HashAlgorithm.Algorithm)
	}
}

func TestBuildRequestRejectsShortDigest(t *testing.T) {
	if _, _, err := rfc3161.BuildRequest([]byte{1, 2, 3}, rfc3161.RequestOptions{}); err == nil {
		t.Fatal("build request accepted a truncated digest")
	}
}

func TestParseTokenRejectsGarbage(t *testing.T) {
	if _, err := rfc3161.ParseToken([]byte("not DER at all")); err == nil {
		t.Fatal("parse accepted non-DER input")
	}
}

func TestSignerCertificateIsTheTimestampingLeaf(t *testing.T) {
	digest := digestOf("manifest bytes")
	tok := stamp(t, digest, tsatest.StampOptions{})

	if !tok.Signer.Equal(testAuthority.TSACert) {
		t.Errorf("signer = %s, want the TSA leaf", tok.Signer.Subject)
	}
	if len(tok.Certificates) != 2 {
		t.Errorf("embedded certificates = %d, want 2", len(tok.Certificates))
	}
	var hasTimestamping bool
	for _, eku := range tok.Signer.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTimestamping = true
		}
	}
	if !hasTimestamping {
		t.Error("signer certificate lacks the timestamping EKU")
	}
}
