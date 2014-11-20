package server

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/MDrollette/go-acme"
)

type inMemoryState struct {
	issuedChallenges  chan map[string]*Challenge
	authorizedKeys    chan map[string][]*acme.Jwk
	recoveryKeys      chan map[string]string
	certificates      chan map[string][]byte
	revocationStatus  chan map[string]bool
	deferredResponses chan map[string]string
}

func newInMemoryState() *inMemoryState {
	s := inMemoryState{
		issuedChallenges:  make(chan map[string]*Challenge, 1),
		authorizedKeys:    make(chan map[string][]*acme.Jwk, 1),
		recoveryKeys:      make(chan map[string]string, 1),
		certificates:      make(chan map[string][]byte, 1),
		revocationStatus:  make(chan map[string]bool, 1),
		deferredResponses: make(chan map[string]string, 1),
	}

	s.issuedChallenges <- make(map[string]*Challenge)
	s.authorizedKeys <- make(map[string][]*acme.Jwk)
	s.recoveryKeys <- make(map[string]string)
	s.certificates <- make(map[string][]byte)
	s.revocationStatus <- make(map[string]bool)
	s.deferredResponses <- make(map[string]string)

	return &s
}

func (s *inMemoryState) IssuedChallenge(nonce string) (*Challenge, error) {
	db := <-s.issuedChallenges
	defer func() { s.issuedChallenges <- db }()

	for key, value := range db {
		if key == nonce {
			return value, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("No issued challenges for nonce '%s'", nonce))
}

func (s *inMemoryState) SetIssuedChallenge(nonce string, challenge *Challenge) error {
	db := <-s.issuedChallenges
	defer func() { s.issuedChallenges <- db }()

	if _, exists := db[nonce]; exists {
		return errors.New(fmt.Sprintf("Challenge already exists for nonce '%s'", nonce))
	}

	db[nonce] = challenge

	return nil
}

func (s *inMemoryState) AuthorizedKeys(identifier string) ([]*acme.Jwk, error) {
	db := <-s.authorizedKeys
	defer func() { s.authorizedKeys <- db }()

	for key, value := range db {
		if key == identifier {
			return value, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("No keys for identifier '%s'", identifier))
}

func (s *inMemoryState) SetAuthorizedKeys(identifier string, keys ...*acme.Jwk) error {
	db := <-s.authorizedKeys
	defer func() { s.authorizedKeys <- db }()

	if _, exists := db[identifier]; !exists {
		db[identifier] = make([]*acme.Jwk, 0)
	}

	db[identifier] = append(db[identifier], keys...)

	return nil
}

func (s *inMemoryState) RecoveryKey(rkey string) (string, error) {
	db := <-s.recoveryKeys
	defer func() { s.recoveryKeys <- db }()

	for key, value := range db {
		if key == rkey {
			return value, nil
		}
	}

	return "", errors.New(fmt.Sprintf("Invalid recovery key '%s'", rkey))
}

func (s *inMemoryState) SetRecoveryKey(key, identifier string) error {
	db := <-s.recoveryKeys
	defer func() { s.recoveryKeys <- db }()

	if _, exists := db[key]; exists {
		return errors.New(fmt.Sprintf("The key '%s' is already in use", key))
	}

	db[key] = identifier

	return nil
}

func (s *inMemoryState) Certificate(serial string) ([]byte, error) {
	db := <-s.certificates
	defer func() { s.certificates <- db }()

	for key, value := range db {
		if key == serial {
			return value, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("No certificates for serial '%s'", serial))
}

func (s *inMemoryState) SetCertificate(serial string, certificate []byte) error {
	db := <-s.certificates
	defer func() { s.certificates <- db }()

	if _, exists := db[serial]; exists {
		return errors.New(fmt.Sprintf("The serial '%s' has already been issued", serial))
	}

	db[serial] = certificate

	return nil
}

func (s *inMemoryState) RevocationStatus(fingerprint string) (bool, error) {
	db := <-s.revocationStatus
	defer func() { s.revocationStatus <- db }()

	for key, value := range db {
		if key == fingerprint {
			return value, nil
		}
	}

	return true, errors.New(fmt.Sprintf("No revocation status for certificate '%s'", fingerprint))
}

func (s *inMemoryState) SetRevocationStatus(fingerprint string, status bool) error {
	db := <-s.revocationStatus
	defer func() { s.revocationStatus <- db }()

	db[fingerprint] = status

	return nil
}

func (s *inMemoryState) DeferredResponse(token string) (string, error) {
	db := <-s.deferredResponses
	defer func() { s.deferredResponses <- db }()

	for key, value := range db {
		if key == token {
			return value, nil
		}
	}

	return "", errors.New(fmt.Sprintf("No deferred responses for token '%s'", token))
}

func (s *inMemoryState) SetDeferredResponse(token, response string) error {
	db := <-s.deferredResponses
	defer func() { s.deferredResponses <- db }()

	db[token] = response

	return nil
}

func (s *inMemoryState) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("===============\n")

	db := <-s.issuedChallenges
	defer func() { s.issuedChallenges <- db }()
	buffer.WriteString("issuedChallenges: ")
	for key, value := range db {
		buffer.WriteString(fmt.Sprintf("%s:%s\n", key, value))
	}

	buffer.WriteString("-------------\n")

	db2 := <-s.authorizedKeys
	defer func() { s.authorizedKeys <- db2 }()
	buffer.WriteString("authorizedKeys: ")
	for key, value := range db2 {
		buffer.WriteString(fmt.Sprintf("%s:%s\n", key, value))
	}
	buffer.WriteString("===============\n")

	return buffer.String()
}
