package acme

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Base64Encode encodes the given data using the standard base64 url
// encoding format but with all trailing '=' characters ommitted in accordance
// with the jose specification.
// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-2
func Base64Encode(b []byte) string {
	s := strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	// s = strings.Replace(s, "+", "-", -1)
	// s = strings.Replace(s, "/", "_", -1)
	return s
}

// Base64Decode decodes the given string using the standard base64 url
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

var (
	// A-Z, a-z, 0-9, and hyphen are the only valid characters for domains.
	domainTable = &unicode.RangeTable{
		R16: []unicode.Range16{
			{'-', '-', 1},
			{'0', '9', 1},
			{'A', 'Z', 1},
			{'a', 'z', 1},
		},
		LatinOffset: 4,
	}
)

// Checks for a valid domain name. Checks lengths, characters, and looks for a
// valid TLD (according to IANA).
func ValidDomain(s string) error {
	p := []byte(s)
	//func IsDomain(p []byte) (res validate.Result) {
	// Domain rules:
	// - 255 character total length max
	// - 63 character label max
	// - 127 sub-domains
	// - Characters a-z, A-Z, 0-9, and -
	// - Labels may not start or end with -
	// - TLD may not be all numeric

	// Check for max length.
	// NOTE: Invalid unicode will count as a 1 byte rune, but we'll catch that later.
	if utf8.RuneCount(p) > 255 {
		return fmt.Errorf("Invalid domain. Length is greater than 255.")
	}

	// First we split by label
	domain := bytes.Split(p, []byte("."))
	// 127 sub-domains max (not including TLD)
	if len(domain) > 128 {
		return fmt.Errorf("Invalid domain. Contains more than 128 subdomains.")
	}

	// Check each domain for valid characters
	for _, subDomain := range domain {
		length := len(subDomain)
		// Check for a domain with two periods next to eachother.
		if length < 1 {
			return fmt.Errorf("Invalid domain.")
		}

		// Check 63 character max.
		if length > 63 {
			return fmt.Errorf("Invalid domain.")
		}

		// Check that label doesn't start or end with hyphen.
		r, size := utf8.DecodeRune(subDomain)
		if r == utf8.RuneError && size == 1 {
			// Invalid rune
			return fmt.Errorf("Invalid domain.")
		}

		if r == '-' {
			return fmt.Errorf("Invalid domain.")
		}

		r, size = utf8.DecodeLastRune(subDomain)
		if r == utf8.RuneError && size == 1 {
			// Invalid rune
			return fmt.Errorf("Invalid domain.")
		}

		if r == '-' {
			return fmt.Errorf("Invalid domain.")
		}

		// Now we check each rune individually to make sure its valid unicode
		// and an acceptable character.
		for i := 0; i < length; {
			if subDomain[i] < utf8.RuneSelf {
				// Check if it's a valid domain character
				if !unicode.Is(domainTable, rune(subDomain[i])) {
					return fmt.Errorf("Invalid domain.")
				}
				i++
			} else {
				r, size := utf8.DecodeRune(subDomain[i:])
				if size == 1 {
					// All valid runes of size 1 (those
					// below RuneSelf) were handled above.
					// This must be a RuneError.
					return fmt.Errorf("Invalid domain.")
				}
				// Check if it's a valid domain character
				if !unicode.Is(domainTable, r) {
					return fmt.Errorf("Invalid domain.")
				}
				i += size
			}
		}
	}

	return nil
}
