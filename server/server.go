package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/MDrollette/go-acme"
	"github.com/justinas/alice"
)

const (
	NONCE_BYTES = 16
)

type Server struct {
	*http.Server
}

type context struct {
	Service     *Service
	RawMessage  []byte
	RequestType string
}

func (s *Server) Start() error {
	return s.ListenAndServeTLS("server.crt", "server.key")
}

func NewServer() *Server {
	service := NewService(newInMemoryState())

	appC := context{Service: service}
	commonHandlers := alice.New(loggingHandler, appC.requestProcessor, appC.debugHandler)
	http.Handle("/acme", commonHandlers.ThenFunc(appC.handleRequest))

	config := &tls.Config{MinVersion: tls.VersionTLS10}
	return &Server{Server: &http.Server{Addr: "127.0.0.1:9999", TLSConfig: config}}
}

func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()
		log.Printf("[%s] %q %v\n", r.Method, r.URL.String(), t2.Sub(t1))
	}

	return http.HandlerFunc(fn)
}

func (c *context) debugHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		fmt.Printf("%s\n", c.Service.state)
	}

	return http.HandlerFunc(fn)
}

func (c *context) requestProcessor(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		jsonStr, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Fprintf(w, "Error:", err)
			return
		}

		c.RawMessage = jsonStr

		data := struct {
			Type string `json:"type"`
		}{}
		err = json.Unmarshal(jsonStr, &data)
		if err != nil {
			fmt.Fprintf(w, "Error:", err)
			return
		}

		c.RequestType = data.Type

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func (c *context) handleError(w http.ResponseWriter, r *http.Request) {
	response := acme.NewErrorMessage()

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleStatus(w http.ResponseWriter, r *http.Request) {
	request := acme.StatusRequestMessage{}
	err := json.Unmarshal(c.RawMessage, &request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response := acme.NewDeferMessage()

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleChallenge(w http.ResponseWriter, r *http.Request) {
	request := acme.ChallengeRequestMessage{}
	err := json.Unmarshal(c.RawMessage, &request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	// generate a nonce
	b := make([]byte, NONCE_BYTES)
	_, err = rand.Read(b)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}
	nonce := acme.Base64Encode(b)

	// generate a session ID, which we don't actually use
	s := make([]byte, NONCE_BYTES)
	_, err = rand.Read(s)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}
	sessionId := acme.Base64Encode(s)

	// we don't have any challenges yet
	var challenges []*acme.ChallengeType

	// save the state of this nonce/challenges
	c.Service.state.SetIssuedChallenge(nonce, &Challenge{
		Identifier: request.Identifier,
		Challenges: challenges,
	})

	response := acme.NewChallengeMessage()
	response.Nonce = nonce
	response.Challenges = challenges
	response.SessionId = sessionId

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	request := acme.AuthorizationRequestMessage{}
	err := json.Unmarshal(c.RawMessage, &request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response := acme.NewAuthorizationMessage()

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleCertificate(w http.ResponseWriter, r *http.Request) {
	request := acme.StatusRequestMessage{}
	err := json.Unmarshal(c.RawMessage, &request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response := acme.NewCertificateMessage()

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleRevocation(w http.ResponseWriter, r *http.Request) {
	request := acme.StatusRequestMessage{}
	err := json.Unmarshal(c.RawMessage, &request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response := acme.NewRevocationMessage()

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleRequest(w http.ResponseWriter, r *http.Request) {
	switch c.RequestType {
	case "statusRequest":
		c.handleStatus(w, r)
	case "challengeRequest":
		c.handleChallenge(w, r)
	case "authorizationRequest":
		c.handleAuthorization(w, r)
	case "certificateRequest":
		c.handleCertificate(w, r)
	case "revocationRequest":
		c.handleRevocation(w, r)
	default:
		c.handleError(w, r)
	}
}
