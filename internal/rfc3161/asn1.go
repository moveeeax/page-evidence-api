// Package rfc3161 implements the subset of RFC 3161 and CMS (RFC 5652) that a
// trusted-timestamp verifier needs: build a TimeStampReq, parse a
// TimeStampResp, and verify the enclosed token offline against a digest.
//
// It is deliberately stdlib-only. A verifier that a compliance team can
// rebuild from source with `go build` and no module downloads is easier to
// trust than one that pulls a dependency tree.
package rfc3161

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// Object identifiers used by RFC 3161 timestamp tokens.
var (
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMsgDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCert  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCert2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// algorithmIdentifier is the CMS AlgorithmIdentifier.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// MessageImprint is the hash of the data being timestamped.
type MessageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

// Hash returns the crypto.Hash named by the imprint's algorithm identifier.
func (m MessageImprint) Hash() (crypto.Hash, error) { return hashByOID(m.HashAlgorithm.Algorithm) }

type timeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"optional,tag:0"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// TSTInfo is the signed payload of a timestamp token: what was hashed, when,
// and under which policy.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	// GenTime is kept raw because Go's asn1 GeneralizedTime parser rejects the
	// fractional seconds that several public TSAs emit.
	GenTime    asn1.RawValue
	Accuracy   accuracy      `asn1:"optional"`
	Ordering   bool          `asn1:"optional,default:false"`
	Nonce      *big.Int      `asn1:"optional"`
	TSA        asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions asn1.RawValue `asn1:"optional,tag:1"`
}

// Time decodes the token's genTime as UTC.
func (t TSTInfo) Time() (time.Time, error) {
	return parseGeneralizedTime(t.GenTime)
}

// AccuracySeconds returns the TSA's stated accuracy as a duration. Zero means
// the TSA did not state one.
func (t TSTInfo) AccuracySeconds() time.Duration {
	return time.Duration(t.Accuracy.Seconds)*time.Second +
		time.Duration(t.Accuracy.Millis)*time.Millisecond +
		time.Duration(t.Accuracy.Micros)*time.Microsecond
}

// parseGeneralizedTime accepts the ASN.1 GeneralizedTime forms a TSA may emit:
// with or without fractional seconds, always UTC ("Z") as DER requires.
func parseGeneralizedTime(rv asn1.RawValue) (time.Time, error) {
	if rv.Tag != asn1.TagGeneralizedTime || len(rv.Bytes) == 0 {
		return time.Time{}, fmt.Errorf("genTime: expected GeneralizedTime, got tag %d", rv.Tag)
	}
	s := string(rv.Bytes)
	layouts := []string{
		"20060102150405Z",
		"20060102150405.0Z",
		"20060102150405.00Z",
		"20060102150405.000Z",
		"20060102150405.000000Z",
		"20060102150405-0700",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("genTime: cannot parse %q as GeneralizedTime", s)
}

func hashByOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	case oid.Equal(oidSHA1):
		return crypto.SHA1, nil
	default:
		return 0, fmt.Errorf("unsupported digest algorithm %v", oid)
	}
}

func oidByHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidSHA256, nil
	case crypto.SHA384:
		return oidSHA384, nil
	case crypto.SHA512:
		return oidSHA512, nil
	case crypto.SHA1:
		return oidSHA1, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %v", h)
	}
}
