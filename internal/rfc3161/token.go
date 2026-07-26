package rfc3161

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PKI status values from RFC 3161 section 2.4.2.
const (
	StatusGranted                = 0
	StatusGrantedWithMods        = 1
	StatusRejection              = 2
	StatusWaiting                = 3
	StatusRevocationWarning      = 4
	StatusRevocationNotification = 5
)

// StatusText renders a PKIStatus for humans.
func StatusText(status int) string {
	switch status {
	case StatusGranted:
		return "granted"
	case StatusGrantedWithMods:
		return "granted with modifications"
	case StatusRejection:
		return "rejected"
	case StatusWaiting:
		return "waiting"
	case StatusRevocationWarning:
		return "revocation warning"
	case StatusRevocationNotification:
		return "revocation notification"
	default:
		return fmt.Sprintf("unknown status %d", status)
	}
}

// RequestOptions tunes a TimeStampReq.
type RequestOptions struct {
	// Hash is the algorithm that produced the digest. Defaults to SHA-256.
	Hash crypto.Hash
	// Policy optionally pins the TSA policy the caller will accept.
	Policy asn1.ObjectIdentifier
	// Nonce is echoed back by the TSA. Zero means "generate a random one",
	// which is what callers should do: it is the only replay protection a
	// timestamp request has.
	Nonce *big.Int
	// NoCertReq suppresses the request for the TSA certificate chain. Leave it
	// false: without the certificates the token cannot be verified offline,
	// which is the entire point of a sealed bundle.
	NoCertReq bool
}

// BuildRequest encodes a DER TimeStampReq over digest.
func BuildRequest(digest []byte, opts RequestOptions) ([]byte, *big.Int, error) {
	h := opts.Hash
	if h == 0 {
		h = crypto.SHA256
	}
	if len(digest) != h.Size() {
		return nil, nil, fmt.Errorf("timestamp request: digest is %d bytes, %v needs %d", len(digest), h, h.Size())
	}
	oid, err := oidByHash(h)
	if err != nil {
		return nil, nil, err
	}
	nonce := opts.Nonce
	if nonce == nil {
		nonce, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
		if err != nil {
			return nil, nil, fmt.Errorf("timestamp request: generate nonce: %w", err)
		}
	}
	req := timeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  oid,
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: digest,
		},
		ReqPolicy: opts.Policy,
		Nonce:     nonce,
		CertReq:   !opts.NoCertReq,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp request: marshal: %w", err)
	}
	return der, nonce, nil
}

// Response is a parsed TimeStampResp.
type Response struct {
	Status       int
	StatusString []string
	FailInfo     asn1.BitString
	// TokenDER is the DER of the enclosed TimeStampToken, empty if the TSA
	// refused the request.
	TokenDER []byte
}

// ParseResponse decodes a DER TimeStampResp.
func ParseResponse(der []byte) (*Response, error) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return nil, fmt.Errorf("parse TimeStampResp: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("parse TimeStampResp: %d trailing bytes", len(rest))
	}
	return &Response{
		Status:       resp.Status.Status,
		StatusString: resp.Status.StatusString,
		FailInfo:     resp.Status.FailInfo,
		TokenDER:     resp.TimeStampToken.FullBytes,
	}, nil
}

// Granted reports whether the TSA issued a token.
func (r *Response) Granted() bool {
	return (r.Status == StatusGranted || r.Status == StatusGrantedWithMods) && len(r.TokenDER) > 0
}

// Token is a parsed and structurally validated RFC 3161 timestamp token.
type Token struct {
	Info         TSTInfo
	Certificates []*x509.Certificate
	// Signer is the certificate identified by the token's SignerInfo.
	Signer *x509.Certificate

	eContent           []byte
	signedAttrsDER     []byte
	signedAttrs        []attribute
	digestAlgorithm    crypto.Hash
	signatureAlgorithm asn1.ObjectIdentifier
	signature          []byte
}

// ParseToken decodes a DER TimeStampToken (a CMS ContentInfo wrapping
// SignedData whose encapsulated content is a TSTInfo).
func ParseToken(der []byte) (*Token, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("parse timestamp token: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("parse timestamp token: content type is %v, want CMS SignedData", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("parse SignedData: %w (a token issued without certReq cannot be verified offline)", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidCTTSTInfo) {
		return nil, fmt.Errorf("parse SignedData: encapsulated content type is %v, want id-ct-TSTInfo", sd.EncapContentInfo.EContentType)
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return nil, errors.New("parse SignedData: token carries no TSTInfo")
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("parse SignedData: %d SignerInfos, want exactly 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]

	var info TSTInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return nil, fmt.Errorf("parse TSTInfo: %w", err)
	}
	if info.Version != 1 {
		return nil, fmt.Errorf("parse TSTInfo: version %d, want 1", info.Version)
	}
	if _, err := info.Time(); err != nil {
		return nil, fmt.Errorf("parse TSTInfo: %w", err)
	}

	var certs []*x509.Certificate
	if sd.Certificates.Class == asn1.ClassContextSpecific && sd.Certificates.Tag == 0 {
		var err error
		certs, err = x509.ParseCertificates(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse token certificates: %w", err)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("parse timestamp token: no certificates embedded; the token cannot be verified offline")
	}

	if si.SignedAttrs.Class != asn1.ClassContextSpecific || si.SignedAttrs.Tag != 0 {
		return nil, errors.New("parse SignerInfo: token has no signed attributes")
	}
	attrs, err := parseAttributes(si.SignedAttrs.Bytes)
	if err != nil {
		return nil, err
	}
	digestAlg, err := hashByOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("parse SignerInfo: %w", err)
	}

	signer, err := findSigner(certs, si.SID)
	if err != nil {
		return nil, err
	}

	// The signature covers the signed attributes re-encoded as a SET OF, not
	// as the implicitly tagged [0] they appear as inside the SignerInfo.
	signedAttrsDER := make([]byte, len(si.SignedAttrs.FullBytes))
	copy(signedAttrsDER, si.SignedAttrs.FullBytes)
	signedAttrsDER[0] = 0x31 // universal, constructed, SET

	return &Token{
		Info:               info,
		Certificates:       certs,
		Signer:             signer,
		eContent:           sd.EncapContentInfo.EContent,
		signedAttrsDER:     signedAttrsDER,
		signedAttrs:        attrs,
		digestAlgorithm:    digestAlg,
		signatureAlgorithm: si.SignatureAlgorithm.Algorithm,
		signature:          si.Signature,
	}, nil
}

func parseAttributes(der []byte) ([]attribute, error) {
	var out []attribute
	rest := der
	for len(rest) > 0 {
		var attr attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil, fmt.Errorf("parse signed attributes: %w", err)
		}
		out = append(out, attr)
	}
	if len(out) == 0 {
		return nil, errors.New("parse signed attributes: none present")
	}
	return out, nil
}

func (t *Token) attr(oid asn1.ObjectIdentifier) (attribute, bool) {
	for _, a := range t.signedAttrs {
		if a.Type.Equal(oid) {
			return a, true
		}
	}
	return attribute{}, false
}

// findSigner resolves the SignerIdentifier against the embedded certificates.
// Both CMS forms are supported: issuerAndSerialNumber and subjectKeyIdentifier.
func findSigner(certs []*x509.Certificate, sid asn1.RawValue) (*x509.Certificate, error) {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		want := sid.Bytes
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, want) {
				return c, nil
			}
		}
		return nil, errors.New("signer certificate: no embedded certificate matches the subject key identifier")
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil, fmt.Errorf("signer certificate: parse issuerAndSerialNumber: %w", err)
	}
	for _, c := range certs {
		if c.SerialNumber.Cmp(ias.Serial) == 0 && bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("signer certificate: no embedded certificate has issuer/serial %s", ias.Serial)
}

// GenTime is the instant the TSA asserts it saw the digest.
func (t *Token) GenTime() (time.Time, error) { return t.Info.Time() }
