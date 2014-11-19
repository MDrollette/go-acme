package acme

type BaseMessage struct {
	Type string `json:"type"`
}

type ErrorMessage struct {
	*BaseMessage // error

	// malformed      The request message was malformed
	// unauthorized   The client lacks sufficient authorization
	// serverInternal The server experienced an internal error
	// notSupported   The request type is not supported
	// unknown        The server does not recognize an ID/token in the request
	// badCSR         The CSR is unacceptable (e.g., due to a short key)
	Error    string `json:"error"`
	Message  string `json:"message,omitempty"`
	MoreInfo string `json:"moreInfo,omitempty"`
}

type DeferMessage struct {
	*BaseMessage        // defer
	Token        string `json:"token"`
	Interval     int64  `json:"interval,omitempty"`
	Message      string `json:"message,omitempty"`
}

type StatusRequestMessage struct {
	*BaseMessage        // statusRequest
	Token        string `json:"token"`
}

type Signature struct {
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
	Nonce string `json:"nonce"`
	Jwk   *Jwk   `json:"jwk"`
}

type Jwk struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
}

type ChallengeRequestMessage struct {
	*BaseMessage        // challengeRequest
	Identifier   string `json:"identifier"`
}

type ChallengeMessage struct {
	*BaseMessage                // challenge
	SessionId    string         `json:"sessionID"`
	Nonce        string         `json:"nonce"`
	Challenges   []*Challenge   `json:"challenges"`
	Combinations [][]*Challenge `json:"combinations,omitempty"`
}

type Challenge struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

type AuthorizationRequestMessage struct {
	*BaseMessage                      // authorizationRequest
	SessionId    string               `json:"sessionID"`
	Nonce        string               `json:"nonce"`
	Signature    *Signature           `json:"signature"`
	Responses    []*ChallengeResponse `json:"responses"`
	Contact      []string             `json:"contact,omitempty"`
}

type ChallengeResponse map[string]string

type Authorization struct {
	*BaseMessage         // authorization
	RecoveryToken string `json:"recoveryToken,omitempty"`
	Identifier    string `json:"identifier,omitempty"`
	Jwk           *Jwk   `json:"jwk,omitempty"`
}

type CertificateRequestMessage struct {
	*BaseMessage            // certificateRequest
	Csr          string     `json:"csr"`
	Signature    *Signature `json:"signature"`
}

type CertificateMessage struct {
	*BaseMessage          // challenge
	Certificate  string   `json:"certificate"`
	Chain        []string `json:"chain,omitempty"`
	Refresh      string   `json:"refresh,omitempty"`
}

type RevocationRequestMessage struct {
	*BaseMessage            // revocationRequest
	Certificate  string     `json:"certificate"`
	Signature    *Signature `json:"signature"`
}

type RevocationMessage struct {
	*BaseMessage // revocation
}
