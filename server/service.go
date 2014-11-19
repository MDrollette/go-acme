package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/MDrollette/go-acme"
)

const (
	CA_KEY_SIZE = 2048
)

type Service struct {
	keyPair     *rsa.PrivateKey
	certificate x509.Certificate
	state       State
}

func NewService(s State) *Service {
	sc := Service{state: s}

	if keyPair, err := rsa.GenerateKey(rand.Reader, CA_KEY_SIZE); err == nil {
		sc.keyPair = keyPair
	}

	return &sc
}

type Challenge struct {
	Identifier string
	Challenges []*acme.ChallengeType
}

type State interface {
	IssuedChallenge(nonce string) (*Challenge, error)
	SetIssuedChallenge(nonce string, challenge *Challenge) error

	AuthorizedKey(identifier string) ([]*acme.Jwk, error)
	SetAuthorizedKeys(identifier string, keys ...*acme.Jwk) error

	RecoveryKey(key string) (string, error)
	SetRecoveryKey(key, identifier string) error

	Certificate(serial string) (*x509.Certificate, error)
	SetCertificate(serial string, certificate *x509.Certificate) error

	RevocationStatus(fingerprint string) (bool, error)
	SetRevocationStatus(fingerprint string, status bool) error

	DeferredResponse(token string) (string, error)
	SetDeferredResponse(token, response string) error
}
