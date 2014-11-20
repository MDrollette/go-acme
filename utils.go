package acme

import (
	"encoding/base64"
	"errors"
	"strings"
)

// joseBase64UrlEncode encodes the given data using the standard base64 url
// encoding format but with all trailing '=' characters ommitted in accordance
// with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func Base64Encode(b []byte) string {
	s := strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	s = strings.Replace(s, "+", "-", -1)
	s = strings.Replace(s, "/", "_", -1)
	return s
}

// joseBase64UrlDecode decodes the given string using the standard base64 url
// decoder but first adds the appropriate number of trailing '=' characters in
// accordance with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func Base64Decode(s string) ([]byte, error) {
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
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
