package acme

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

func VerifySignature(sig *Signature, content []byte) (bool, error) {
	if sig.Jwk.Kty != "RSA" {
		// Unsupported key type
		return false, errors.New("Unsupported key type")
	}

	// Compute signature input
	nonceDec, err := Base64Decode(sig.Nonce)
	if nil != err {
		return false, err
	}
	if len(nonceDec) != 16 {
		return false, fmt.Errorf("Invalid nonce length %d", len(nonceDec))
	}
	signatureInput := append(nonceDec, content...)

	// Compute message digest
	var hashType crypto.Hash
	switch sig.Alg {
	case "RS1":
		hashType = crypto.SHA1
	case "RS256":
		hashType = crypto.SHA256
	case "RS384":
		hashType = crypto.SHA384
	case "RS512":
		hashType = crypto.SHA512
	default:
		return false, errors.New("Unsupported algorithm")
	}
	if !hashType.Available() {
		return false, errors.New("Unsupported algorithm")
	}
	h := hashType.New()
	h.Write(signatureInput)

	publicKey, err := rsaPublicKeyFromJwk(sig.Jwk)
	if nil != err {
		return false, err
	}

	sigThing, err := Base64Decode(sig.Sig)
	if nil != err {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(publicKey, hashType, h.Sum(nil), sigThing)
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

	// only support RSA keys
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashType, h.Sum(nil), csr.Signature)
	}

	return x509.ErrUnsupportedAlgorithm
}

func rsaPublicKeyFromJwk(jwk Jwk) (*rsa.PublicKey, error) {
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
