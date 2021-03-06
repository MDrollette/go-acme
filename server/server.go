package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/MDrollette/go-acme/acme"
	"github.com/justinas/alice"
)

type Server struct {
	*http.Server
	CertPath string
	KeyPath  string
}

type context struct {
	Service     *Service
	RawMessage  []byte
	RequestType string
}

func (s *Server) Start() error {
	log.Println("ACME server listening on", s.Addr)
	return s.ListenAndServeTLS(s.CertPath, s.KeyPath)
}

func NewServer(service *Service) *Server {
	appC := context{Service: service}

	commonHandlers := alice.New(loggingHandler, appC.requestProcessor, appC.debugHandler)
	http.Handle("/", commonHandlers.ThenFunc(appC.handleRequest))

	config := &tls.Config{MinVersion: tls.VersionTLS10}
	return &Server{Server: &http.Server{TLSConfig: config}}
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
		fmt.Printf("Current State: \n%s\n", c.Service.state)
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
	request := &acme.StatusRequestMessage{}
	err := json.Unmarshal(c.RawMessage, request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response := acme.NewDeferMessage()

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleChallenge(w http.ResponseWriter, r *http.Request) {
	request := &acme.ChallengeRequestMessage{}
	err := json.Unmarshal(c.RawMessage, request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response, err := c.Service.ChallengeRequest(request)
	if nil != err {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	request := &acme.AuthorizationRequestMessage{}
	err := json.Unmarshal(c.RawMessage, request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response, err := c.Service.AuthorizationRequest(request)
	if nil != err {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleCertificate(w http.ResponseWriter, r *http.Request) {
	request := &acme.CertificateRequestMessage{}
	err := json.Unmarshal(c.RawMessage, request)
	if err != nil {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	response, err := c.Service.CertificateRequest(request)
	if nil != err {
		fmt.Fprintf(w, "Error:", err)
		return
	}

	json.NewEncoder(w).Encode(response)
}

func (c *context) handleRevocation(w http.ResponseWriter, r *http.Request) {
	request := acme.RevocationRequestMessage{}
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
