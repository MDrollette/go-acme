package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// joseBase64UrlEncode encodes the given data using the standard base64 url
// encoding format but with all trailing '=' characters ommitted in accordance
// with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func Base64Encode(b []byte) string {
	s := strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	// s = strings.Replace(s, "+", "-", -1)
	// s = strings.Replace(s, "/", "_", -1)
	return s
}

// joseBase64UrlDecode decodes the given string using the standard base64 url
// decoder but first adds the appropriate number of trailing '=' characters in
// accordance with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func Base64Decode(s string) ([]byte, error) {
	// s = strings.Replace(s, "-", "+", -1)
	// s = strings.Replace(s, "_", "/", -1)
	switch len(s) % 4 {
	case 0:
	case 2:
		s += "=="
	case 3:
		s += "="
	default:
		return nil, errors.New("illegal base64url string")
	}
	return base64.URLEncoding.DecodeString(s)
}

func VerifySignature(sig Signature, content []byte) (bool, error) {
	// Assumes validSignature(sig)
	if sig.Jwk.Kty != "RSA" {
		// Unsupported key type
		return false, errors.New("Unsupported key type")
	}

	// Compute signature input
	nonceDec, err := Base64Decode(sig.Nonce)
	if nil != err {
		return false, err
	}
	signatureInput := append(nonceDec, content...)

	// Compute message digest
	var hasher hash.Hash
	var hashType crypto.Hash
	switch sig.Alg {
	case "RS1":
		hasher = sha1.New()
		hashType = crypto.SHA1
		break
	case "RS256":
		hasher = sha256.New()
		hashType = crypto.SHA256
		break
	case "RS384":
		hasher = sha512.New384()
		hashType = crypto.SHA384
		break
	case "RS512":
		hasher = sha512.New()
		hashType = crypto.SHA512
		break
	default:
		return false, errors.New("Unsupported algorithm")
	}
	hasher.Write(signatureInput)

	publicKey, err := rsaPublicKeyFromJwk(&sig.Jwk)
	if nil != err {
		return false, err
	}

	sigThing, err := Base64Decode(sig.Sig)
	if nil != err {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(publicKey, hashType, hasher.Sum(nil), sigThing)
	if nil != err {
		return false, err
	}

	return true, nil
}

func VerifyCsr(csr *x509.CertificateRequest) error {
	var hashType crypto.Hash

	switch csr.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA:
		hashType = crypto.SHA512
	default:
		return x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(csr.RawTBSCertificateRequest)
	digest := h.Sum(nil)

	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, digest, csr.Signature)
	}

	return x509.ErrUnsupportedAlgorithm
}

func rsaPublicKeyFromJwk(jwk *Jwk) (*rsa.PublicKey, error) {
	n, err := parseRSAModulusParam(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	e, err := parseRSAPublicExponentParam(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseRSAModulusParam(nB64Url string) (*big.Int, error) {
	nBytes, err := Base64Decode(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}

	return new(big.Int).SetBytes(nBytes), nil
}

func parseRSAPublicExponentParam(eB64Url string) (int, error) {
	eBytes, err := Base64Decode(eB64Url)
	if err != nil {
		return 0, fmt.Errorf("invalid base64 URL encoding: %s", err)
	}

	byteLen := len(eBytes)
	buf := make([]byte, 4-byteLen, 4)
	eBytes = append(buf, eBytes...)

	return int(binary.BigEndian.Uint32(eBytes)), nil
}

func CreateCertificateAuthority(key *rsa.PrivateKey) (*x509.Certificate, error) {
	authPkixName := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Go"},
		OrganizationalUnit: []string{"CA"},
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "",
	}

	authTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               authPkixName,
		NotBefore:             time.Now().Add(-600).UTC(),
		NotAfter:              time.Now().AddDate(1, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           nil,
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: true,
		IsCA:                        true,
		MaxPathLen:                  0,
		DNSNames:                    nil,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, &authTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(crtBytes)
}
