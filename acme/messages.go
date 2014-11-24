package acme

type Signature struct {
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
	Nonce string `json:"nonce"`
	Jwk   Jwk    `json:"jwk"`
}

type Jwk struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
}

type ChallengeType struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

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

func NewErrorMessage() ErrorMessage {
	return ErrorMessage{BaseMessage: &BaseMessage{Type: "error"}}
}

type DeferMessage struct {
	*BaseMessage        // defer
	Token        string `json:"token"`
	Interval     int64  `json:"interval,omitempty"`
	Message      string `json:"message,omitempty"`
}

func NewDeferMessage() DeferMessage {
	return DeferMessage{BaseMessage: &BaseMessage{Type: "defer"}}
}

type StatusRequestMessage struct {
	*BaseMessage        // statusRequest
	Token        string `json:"token"`
}

func NewStatusRequestMessage() StatusRequestMessage {
	return StatusRequestMessage{BaseMessage: &BaseMessage{"statusRequest"}}
}

type ChallengeRequestMessage struct {
	*BaseMessage        // challengeRequest
	Identifier   string `json:"identifier"`
}

type ChallengeMessage struct {
	*BaseMessage                    // challenge
	SessionId    string             `json:"sessionID"`
	Nonce        string             `json:"nonce"`
	Challenges   []*ChallengeType   `json:"challenges"`
	Combinations [][]*ChallengeType `json:"combinations,omitempty"`
}

func NewChallengeMessage() ChallengeMessage {
	return ChallengeMessage{BaseMessage: &BaseMessage{"challenge"}, Challenges: make([]*ChallengeType, 0)}
}

type AuthorizationRequestMessage struct {
	*BaseMessage                     // authorizationRequest
	SessionId    string              `json:"sessionID"`
	Nonce        string              `json:"nonce"`
	Signature    *Signature          `json:"signature"`
	Responses    []map[string]string `json:"responses"`
	Contact      []string            `json:"contact,omitempty"`
}

type AuthorizationMessage struct {
	*BaseMessage         // authorization
	RecoveryToken string `json:"recoveryToken,omitempty"`
	Identifier    string `json:"identifier,omitempty"`
	Jwk           *Jwk   `json:"jwk,omitempty"`
}

func NewAuthorizationMessage() AuthorizationMessage {
	return AuthorizationMessage{BaseMessage: &BaseMessage{"authorization"}}
}

type CertificateRequestMessage struct {
	*BaseMessage            // certificateRequest
	Csr          string     `json:"csr"`
	Signature    *Signature `json:"signature"`
}

type CertificateMessage struct {
	*BaseMessage          // certificate
	Certificate  string   `json:"certificate"`
	Chain        []string `json:"chain,omitempty"`
	Refresh      string   `json:"refresh,omitempty"`
}

func NewCertificateMessage() CertificateMessage {
	return CertificateMessage{BaseMessage: &BaseMessage{"certificate"}}
}

type RevocationRequestMessage struct {
	*BaseMessage            // revocationRequest
	Certificate  string     `json:"certificate"`
	Signature    *Signature `json:"signature"`
}

type RevocationMessage struct {
	*BaseMessage // revocation
}

func NewRevocationMessage() RevocationMessage {
	return RevocationMessage{BaseMessage: &BaseMessage{"revocation"}}
}
