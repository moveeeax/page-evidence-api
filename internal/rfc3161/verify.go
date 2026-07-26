package rfc3161

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// VerifyOptions controls how strictly a token is checked.
type VerifyOptions struct {
	// Digest is the value that must appear in the token's messageImprint.
	// For an evidence bundle this is the SHA-256 of manifest.json.
	Digest []byte
	// Nonce, when set, must match the nonce echoed in the token. Only the
	// process that issued the request can supply this.
	Nonce *big.Int
	// Roots, when set, is the pool the signer certificate must chain to.
	// When nil the chain is not checked and Result.ChainVerified is false:
	// the signature is still proof that whoever holds the TSA key signed this
	// digest, but not proof of who that is.
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

// Result summarises what a token asserts, once verified.
type Result struct {
	GenTime            time.Time
	Accuracy           time.Duration
	SerialNumber       *big.Int
	Policy             string
	Imprint            MessageImprint
	SignerSubject      string
	SignerIssuer       string
	SignerNotAfter     time.Time
	SignatureAlgorithm string
	SigningCertAttr    string
	ChainVerified      bool
	Chains             [][]*x509.Certificate
}

// Verify performs the full offline check of a timestamp token:
//
//  1. the signed attributes carry the right content type and a message digest
//     that matches the encapsulated TSTInfo;
//  2. the signature over those attributes verifies under the signer's key;
//  3. the signer certificate is the one the signingCertificate attribute
//     names, and carries the timestamping extended key usage;
//  4. the TSTInfo message imprint equals the digest we expected;
//  5. the certificate was valid at the asserted time, and (when roots are
//     supplied) chains to a trusted timestamping authority.
//
// Every failure is returned as an error naming the step that failed, because
// "verification failed" is useless in a compliance report.
func (t *Token) Verify(opts VerifyOptions) (*Result, error) {
	if len(opts.Digest) == 0 {
		return nil, errors.New("verify token: no expected digest supplied")
	}

	// 1. content type attribute.
	ct, ok := t.attr(oidAttrContentType)
	if !ok {
		return nil, errors.New("verify token: signed attributes lack a content type")
	}
	var ctOID asn1.ObjectIdentifier
	if len(ct.Values) != 1 {
		return nil, errors.New("verify token: content type attribute must have exactly one value")
	}
	if _, err := asn1.Unmarshal(ct.Values[0].FullBytes, &ctOID); err != nil {
		return nil, fmt.Errorf("verify token: parse content type attribute: %w", err)
	}
	if !ctOID.Equal(oidCTTSTInfo) {
		return nil, fmt.Errorf("verify token: signed content type is %v, want id-ct-TSTInfo", ctOID)
	}

	// 2. message digest attribute must cover the encapsulated TSTInfo.
	md, ok := t.attr(oidAttrMsgDigest)
	if !ok {
		return nil, errors.New("verify token: signed attributes lack a message digest")
	}
	if len(md.Values) != 1 {
		return nil, errors.New("verify token: message digest attribute must have exactly one value")
	}
	var attrDigest []byte
	if _, err := asn1.Unmarshal(md.Values[0].FullBytes, &attrDigest); err != nil {
		return nil, fmt.Errorf("verify token: parse message digest attribute: %w", err)
	}
	h := t.digestAlgorithm.New()
	h.Write(t.eContent)
	if !bytes.Equal(attrDigest, h.Sum(nil)) {
		return nil, errors.New("verify token: signed message digest does not cover the TSTInfo in this token")
	}

	// 3. signature over the DER SET OF signed attributes.
	sigAlg, err := signatureAlgorithm(t.signatureAlgorithm, t.digestAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if err := t.Signer.CheckSignature(sigAlg, t.signedAttrsDER, t.signature); err != nil {
		return nil, fmt.Errorf("verify token: signature does not verify under the signer certificate: %w", err)
	}

	// 4. the signingCertificate attribute binds the signature to this exact
	// certificate, defeating a substituted certificate with the same key.
	signingCertAttr, err := t.checkSigningCertAttr()
	if err != nil {
		return nil, err
	}

	// 5. timestamping extended key usage (RFC 3161 section 2.3: the TSA
	// certificate must have exactly this EKU, and it must be critical).
	if err := checkTimestampingEKU(t.Signer); err != nil {
		return nil, err
	}

	// 6. the imprint must be the digest the caller expected.
	if _, err := t.Info.MessageImprint.Hash(); err != nil {
		return nil, fmt.Errorf("verify token: message imprint: %w", err)
	}
	if !bytes.Equal(t.Info.MessageImprint.HashedMessage, opts.Digest) {
		return nil, fmt.Errorf("verify token: message imprint %x does not match the expected digest %x",
			t.Info.MessageImprint.HashedMessage, opts.Digest)
	}

	// 7. nonce, when the caller kept one.
	if opts.Nonce != nil {
		if t.Info.Nonce == nil || t.Info.Nonce.Cmp(opts.Nonce) != 0 {
			return nil, errors.New("verify token: nonce does not match the request; the response may be a replay")
		}
	}

	genTime, err := t.Info.Time()
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 8. the signer certificate must have been valid when it signed.
	if genTime.Before(t.Signer.NotBefore) || genTime.After(t.Signer.NotAfter) {
		return nil, fmt.Errorf("verify token: asserted time %s falls outside the signer certificate validity %s..%s",
			genTime.Format(time.RFC3339),
			t.Signer.NotBefore.Format(time.RFC3339),
			t.Signer.NotAfter.Format(time.RFC3339))
	}

	res := &Result{
		GenTime:            genTime,
		Accuracy:           t.Info.AccuracySeconds(),
		SerialNumber:       t.Info.SerialNumber,
		Policy:             t.Info.Policy.String(),
		Imprint:            t.Info.MessageImprint,
		SignerSubject:      t.Signer.Subject.String(),
		SignerIssuer:       t.Signer.Issuer.String(),
		SignerNotAfter:     t.Signer.NotAfter,
		SignatureAlgorithm: sigAlg.String(),
		SigningCertAttr:    signingCertAttr,
	}

	// 9. chain, only if the caller supplied a trust anchor.
	if opts.Roots != nil {
		intermediates := opts.Intermediates
		if intermediates == nil {
			intermediates = x509.NewCertPool()
			for _, c := range t.Certificates {
				if c.Equal(t.Signer) {
					continue
				}
				intermediates.AddCert(c)
			}
		}
		chains, err := t.Signer.Verify(x509.VerifyOptions{
			Roots:         opts.Roots,
			Intermediates: intermediates,
			CurrentTime:   genTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		})
		if err != nil {
			return nil, fmt.Errorf("verify token: signer certificate does not chain to a trusted timestamping authority: %w", err)
		}
		res.ChainVerified = true
		res.Chains = chains
	}
	return res, nil
}

func checkTimestampingEKU(cert *x509.Certificate) error {
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping ||
		len(cert.UnknownExtKeyUsage) != 0 {
		return errors.New("verify token: signer certificate is not restricted to the timestamping extended key usage")
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) && !ext.Critical {
			return errors.New("verify token: signer certificate's extended key usage extension is not marked critical")
		}
	}
	return nil
}

type essCertIDv2 struct {
	HashAlgorithm algorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

type essCertID struct {
	CertHash     []byte
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

type signingCertificateV1 struct {
	Certs    []essCertID
	Policies asn1.RawValue `asn1:"optional"`
}

// checkSigningCertAttr validates the ESS signing-certificate attribute if the
// token carries one, and reports which form was used.
func (t *Token) checkSigningCertAttr() (string, error) {
	if a, ok := t.attr(oidAttrSigningCert2); ok {
		if len(a.Values) != 1 {
			return "", errors.New("verify token: signingCertificateV2 must have exactly one value")
		}
		var sc signingCertificateV2
		if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &sc); err != nil {
			return "", fmt.Errorf("verify token: parse signingCertificateV2: %w", err)
		}
		if len(sc.Certs) == 0 {
			return "", errors.New("verify token: signingCertificateV2 names no certificate")
		}
		hashFn := crypto.SHA256
		if len(sc.Certs[0].HashAlgorithm.Algorithm) > 0 {
			var err error
			if hashFn, err = hashByOID(sc.Certs[0].HashAlgorithm.Algorithm); err != nil {
				return "", fmt.Errorf("verify token: signingCertificateV2: %w", err)
			}
		}
		if err := matchCertHash(hashFn, sc.Certs[0].CertHash, t.Signer); err != nil {
			return "", fmt.Errorf("verify token: signingCertificateV2 %w", err)
		}
		return fmt.Sprintf("signingCertificateV2 (%v)", hashFn), nil
	}

	if a, ok := t.attr(oidAttrSigningCert); ok {
		if len(a.Values) != 1 {
			return "", errors.New("verify token: signingCertificate must have exactly one value")
		}
		var sc signingCertificateV1
		if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &sc); err != nil {
			return "", fmt.Errorf("verify token: parse signingCertificate: %w", err)
		}
		if len(sc.Certs) == 0 {
			return "", errors.New("verify token: signingCertificate names no certificate")
		}
		if err := matchCertHash(crypto.SHA1, sc.Certs[0].CertHash, t.Signer); err != nil {
			return "", fmt.Errorf("verify token: signingCertificate %w", err)
		}
		return "signingCertificate (SHA-1)", nil
	}

	return "", errors.New("verify token: no ESS signingCertificate attribute; the token does not bind itself to a certificate")
}

func matchCertHash(h crypto.Hash, want []byte, cert *x509.Certificate) error {
	d := h.New()
	d.Write(cert.Raw)
	if !bytes.Equal(d.Sum(nil), want) {
		return errors.New("names a different certificate than the one that signed the token")
	}
	return nil
}

// signatureAlgorithm resolves the CMS signature algorithm identifier, which may
// name the digest itself or delegate to the SignerInfo digest algorithm.
func signatureAlgorithm(oid asn1.ObjectIdentifier, digest crypto.Hash) (x509.SignatureAlgorithm, error) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}): // rsaEncryption
		switch digest {
		case crypto.SHA256:
			return x509.SHA256WithRSA, nil
		case crypto.SHA384:
			return x509.SHA384WithRSA, nil
		case crypto.SHA512:
			return x509.SHA512WithRSA, nil
		case crypto.SHA1:
			return x509.SHA1WithRSA, nil
		}
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}):
		return x509.SHA256WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}):
		return x509.SHA384WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}):
		return x509.SHA512WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}):
		return x509.SHA1WithRSA, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}): // RSASSA-PSS
		switch digest {
		case crypto.SHA256:
			return x509.SHA256WithRSAPSS, nil
		case crypto.SHA384:
			return x509.SHA384WithRSAPSS, nil
		case crypto.SHA512:
			return x509.SHA512WithRSAPSS, nil
		}
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}): // ecPublicKey
		switch digest {
		case crypto.SHA256:
			return x509.ECDSAWithSHA256, nil
		case crypto.SHA384:
			return x509.ECDSAWithSHA384, nil
		case crypto.SHA512:
			return x509.ECDSAWithSHA512, nil
		}
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}):
		return x509.ECDSAWithSHA256, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}):
		return x509.ECDSAWithSHA384, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}):
		return x509.ECDSAWithSHA512, nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}): // Ed25519
		return x509.PureEd25519, nil
	}
	return 0, fmt.Errorf("unsupported signature algorithm %v with digest %v", oid, digest)
}
