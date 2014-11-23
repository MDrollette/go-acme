package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/MDrollette/go-acme"
	"github.com/nu7hatch/gouuid"
)

const (
	CA_KEY_SIZE = 2048
	NONCE_BYTES = 16
)

type Service struct {
	KeyPair     *rsa.PrivateKey
	Certificate *x509.Certificate
	state       State
}

func NewService(s State) *Service {
	if nil == s {
		s = newInMemoryState()
	}

	return &Service{state: s}
}

func (s *Service) InitCertificateAuthority() error {
	keyPair, err := rsa.GenerateKey(rand.Reader, CA_KEY_SIZE)
	if err != nil {
		fmt.Println(err)
	}
	s.KeyPair = keyPair

	caCert, err := createCACert(s.KeyPair)
	if nil != err {
		return err
	}
	s.Certificate = caCert

	certOut, err := os.Create("ca_cert.pem")
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	certOut.Close()
	log.Println("wrote ca_cert.pem")

	keyOut, err := os.OpenFile("ca_key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyPair)})
	keyOut.Close()
	log.Println("wrote ca_key.pem")

	return nil
}

func (s *Service) ChallengeRequest(message *acme.ChallengeRequestMessage) (*acme.ChallengeMessage, error) {
	// check for valid domain name as the identifier
	if err := acme.ValidDomain(message.Identifier); nil != err {
		return nil, err
	}

	// generate a nonce
	b := make([]byte, NONCE_BYTES)
	if _, err := rand.Read(b); nil != err {
		return nil, err
	}
	nonce := acme.Base64Encode(b)

	// generate a session ID, which we don't actually use
	n := make([]byte, NONCE_BYTES)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	sessionId := acme.Base64Encode(n)

	// we don't have any challenges yet
	challenges := make([]*acme.ChallengeType, 0)

	// save the state of this nonce/challenges
	s.state.SetIssuedChallenge(nonce, &Challenge{
		Identifier: message.Identifier,
		Challenges: challenges,
	})

	response := acme.NewChallengeMessage()
	response.Nonce = nonce
	response.SessionId = sessionId
	response.Challenges = challenges

	return &response, nil
}

func (s *Service) CertificateRequest(message *acme.CertificateRequestMessage) (*acme.CertificateMessage, error) {
	// Validate signature by authorization key
	signatureInput, err := acme.Base64Decode(message.Csr)
	if nil != err {
		return nil, err
	}

	verified, err := acme.VerifySignature(message.Signature, signatureInput)
	if nil != err {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("Unable to verify signature")
	}

	// validate the CSR
	der, err := acme.Base64Decode(message.Csr)
	if nil != err {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if nil != err {
		return nil, err
	}
	err = acme.VerifyCsr(csr)
	if nil != err {
		return nil, err
	}

	// Validate that key is authorized for all domains in this CSR
	err = s.authorizedForIdentifier(csr.Subject.CommonName, &message.Signature.Jwk)
	if nil != err {
		return nil, err
	}

	// Create certificate
	certificate, serialNumber, err := s.createCertificate(csr)
	if nil != err {
		return nil, err
	}

	// Store state about this certificate
	err = s.state.SetCertificate(serialNumber, certificate)
	if nil != err {
		return nil, err
	}

	err = s.state.SetRevocationStatus(string(certificate), false)
	if nil != err {
		return nil, err
	}

	response := acme.NewCertificateMessage()
	response.Certificate = acme.Base64Encode(certificate)

	return &response, nil
}

func (s *Service) AuthorizationRequest(message *acme.AuthorizationRequestMessage) (*acme.AuthorizationMessage, error) {
	ch, err := s.state.IssuedChallenge(message.Nonce)
	if nil != err {
		return nil, err
	}

	// @todo: actually validate something

	s.state.SetAuthorizedKeys(ch.Identifier, &message.Signature.Jwk)
	response := acme.NewAuthorizationMessage()
	return &response, nil
}

func (s *Service) authorizedForIdentifier(identifier string, jwk *acme.Jwk) error {
	keys, err := s.state.AuthorizedKeys(identifier)
	if nil != err {
		return err
	}
	for _, kv := range keys {
		if kv.N == jwk.N {
			return nil
		}
	}

	return fmt.Errorf("This key is not authorized for the identifier '%s'", identifier)
}

func (s *Service) createCertificate(csr *x509.CertificateRequest) ([]byte, string, error) {
	uuid, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}
	serialNumber := new(big.Int).SetBytes(uuid[:])

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().AddDate(1, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	crtHostBytes, err := x509.CreateCertificate(rand.Reader, &template, s.Certificate, csr.PublicKey, s.KeyPair)
	if err != nil {
		return nil, "", err
	}

	return crtHostBytes, serialNumber.String(), nil
}

type Challenge struct {
	Identifier string
	Challenges []*acme.ChallengeType
}

type State interface {
	IssuedChallenge(nonce string) (*Challenge, error)
	SetIssuedChallenge(nonce string, challenge *Challenge) error

	AuthorizedKeys(identifier string) ([]*acme.Jwk, error)
	SetAuthorizedKeys(identifier string, keys ...*acme.Jwk) error

	RecoveryKey(key string) (string, error)
	SetRecoveryKey(key, identifier string) error

	Certificate(serial string) ([]byte, error)
	SetCertificate(serial string, certificate []byte) error

	RevocationStatus(fingerprint string) (bool, error)
	SetRevocationStatus(fingerprint string, status bool) error

	DeferredResponse(token string) (string, error)
	SetDeferredResponse(token, response string) error
}

func createCACert(priv *rsa.PrivateKey) (*x509.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "CA Root",
		},
		NotBefore:             time.Now().Add(-time.Second).UTC(),
		NotAfter:              time.Now().AddDate(1, 0, 0).UTC(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
