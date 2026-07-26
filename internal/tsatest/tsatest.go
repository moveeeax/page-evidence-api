// Package tsatest mints real RFC 3161 timestamp tokens from a throwaway
// certificate authority.
//
// It exists so the verifier can be tested, and the repository's fixture
// bundles generated, without contacting a public TSA over the network. The
// tokens are genuine CMS structures signed by a real key; the only thing that
// makes them worthless as evidence is that nobody trusts the root. Tests pass
// that root in explicitly, exactly as a verifier would be pointed at a real
// TSA root.
package tsatest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrCType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMsgDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSignCert2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEKU           = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidEKUTimeStamp  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidTestPolicy    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
)

// Authority is a self-contained test timestamping authority.
type Authority struct {
	RootCert *x509.Certificate
	TSACert  *x509.Certificate

	rootKey *rsa.PrivateKey
	tsaKey  *rsa.PrivateKey
	serial  int64
}

// StampOptions lets a test bend a token out of shape to check that the
// verifier notices.
type StampOptions struct {
	// GenTime is the time the TSA asserts. Zero means a fixed reference time.
	GenTime time.Time
	// Nonce is echoed into the token.
	Nonce *big.Int
	// OmitSigningCertAttr drops the ESS signingCertificateV2 attribute.
	OmitSigningCertAttr bool
	// CorruptSignature flips a bit in the signature.
	CorruptSignature bool
	// WrongAttrDigest writes a message digest attribute that does not cover
	// the TSTInfo.
	WrongAttrDigest bool
	// Status overrides the PKIStatus (default granted).
	Status int
}

// ReferenceTime is the genTime used when a test does not care.
var ReferenceTime = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// New builds a fresh authority: a root CA and a timestamping leaf.
func New() (*Authority, error) {
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "page-evidence test TSA root", Organization: []string{"page-evidence-api tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	tsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// RFC 3161 requires the timestamping EKU and requires it to be critical,
	// so it is set by hand rather than through x509.Certificate.ExtKeyUsage,
	// which would emit a non-critical extension.
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{oidEKUTimeStamp})
	if err != nil {
		return nil, err
	}
	tsaTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "page-evidence test TSA", Organization: []string{"page-evidence-api tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidEKU, Critical: true, Value: ekuValue}},
	}
	tsaDER, err := x509.CreateCertificate(rand.Reader, tsaTmpl, rootCert, &tsaKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		return nil, err
	}

	return &Authority{RootCert: rootCert, TSACert: tsaCert, rootKey: rootKey, tsaKey: tsaKey, serial: 1000}, nil
}

// RootPEM returns the authority root as PEM, for use as a verifier trust anchor.
func (a *Authority) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.RootCert.Raw})
}

// RootPool returns the authority root as an x509 pool.
func (a *Authority) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.RootCert)
	return pool
}

// ---- ASN.1 shapes needed to emit a token ----

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        asn1.RawValue
	Accuracy       accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
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
	SignerInfos      []signerInfo  `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type pkiStatusInfo struct {
	Status int
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	CertHash []byte
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}

// Stamp issues a DER TimeStampResp over digest.
func (a *Authority) Stamp(digest []byte, opts StampOptions) ([]byte, error) {
	if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("tsatest: digest must be %d bytes", crypto.SHA256.Size())
	}
	genTime := opts.GenTime
	if genTime.IsZero() {
		genTime = ReferenceTime
	}
	a.serial++

	sha256Alg := algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	info := tstInfo{
		Version:        1,
		Policy:         oidTestPolicy,
		MessageImprint: messageImprint{HashAlgorithm: sha256Alg, HashedMessage: digest},
		SerialNumber:   big.NewInt(a.serial),
		GenTime:        asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(genTime.UTC().Format("20060102150405Z"))},
		Accuracy:       accuracy{Seconds: 1},
		Nonce:          opts.Nonce,
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("tsatest: marshal TSTInfo: %w", err)
	}

	ctValue, err := asn1.Marshal(oidCTTSTInfo)
	if err != nil {
		return nil, err
	}
	contentDigest := sha256Sum(infoDER)
	if opts.WrongAttrDigest {
		contentDigest = sha256Sum([]byte("not the TSTInfo"))
	}
	mdValue, err := asn1.Marshal(contentDigest)
	if err != nil {
		return nil, err
	}

	attrs := []attribute{
		{Type: oidAttrCType, Values: []asn1.RawValue{{FullBytes: ctValue}}},
		{Type: oidAttrMsgDigest, Values: []asn1.RawValue{{FullBytes: mdValue}}},
	}
	if !opts.OmitSigningCertAttr {
		scValue, err := asn1.Marshal(signingCertificateV2{Certs: []essCertIDv2{{CertHash: sha256Sum(a.TSACert.Raw)}}})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attribute{Type: oidAttrSignCert2, Values: []asn1.RawValue{{FullBytes: scValue}}})
	}

	// The signature covers the attributes encoded as a DER SET OF.
	signedAttrsSet, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, fmt.Errorf("tsatest: marshal signed attributes: %w", err)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.tsaKey, crypto.SHA256, sha256Sum(signedAttrsSet))
	if err != nil {
		return nil, err
	}
	if opts.CorruptSignature {
		signature[len(signature)-1] ^= 0x01
	}

	// Inside the SignerInfo the same bytes are tagged [0] IMPLICIT.
	implicitAttrs := make([]byte, len(signedAttrsSet))
	copy(implicitAttrs, signedAttrsSet)
	implicitAttrs[0] = 0xA0

	sidDER, err := asn1.Marshal(issuerAndSerial{
		Issuer: asn1.RawValue{FullBytes: a.TSACert.RawIssuer},
		Serial: a.TSACert.SerialNumber,
	})
	if err != nil {
		return nil, err
	}

	sd := signedData{
		Version:          3,
		DigestAlgorithms: []algorithmIdentifier{sha256Alg},
		EncapContentInfo: encapsulatedContentInfo{EContentType: oidCTTSTInfo, EContent: infoDER},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      append(append([]byte{}, a.TSACert.Raw...), a.RootCert.Raw...),
		},
		SignerInfos: []signerInfo{{
			Version:            1,
			SID:                asn1.RawValue{FullBytes: sidDER},
			DigestAlgorithm:    sha256Alg,
			SignedAttrs:        asn1.RawValue{FullBytes: implicitAttrs},
			SignatureAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
			Signature:          signature,
		}},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("tsatest: marshal SignedData: %w", err)
	}

	tokenDER, err := asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: opts.Status},
		TimeStampToken: asn1.RawValue{FullBytes: tokenDER},
	})
}

func sha256Sum(b []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(b)
	return h.Sum(nil)
}
