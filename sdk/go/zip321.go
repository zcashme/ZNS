package zns

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Zip321Parts holds the parsed components of a ZIP-321 zcash: URI.
type Zip321Parts struct {
	Address     string
	Amount      string
	MemoRaw     string
	MemoDecoded string
}

// ToBase64URL encodes a string to base64url (RFC 4648 section 5) without padding.
func ToBase64URL(text string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(text))
}

// DecodeBase64URL decodes a base64url-encoded string (with or without padding).
// Returns an empty string if decoding fails.
func DecodeBase64URL(value string) string {
	// Try without padding first (RawURLEncoding)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		// Try with padding (URLEncoding)
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return ""
		}
	}
	return string(decoded)
}

// BuildZcashURI constructs a ZIP-321 zcash: payment URI.
// The memo should be a plain text string; it will be base64url-encoded automatically.
func BuildZcashURI(address string, amount string, memo string) string {
	encodedMemo := ToBase64URL(memo)
	return fmt.Sprintf("zcash:%s?amount=%s&memo=%s",
		address,
		url.QueryEscape(amount),
		url.QueryEscape(encodedMemo),
	)
}

// ParseZip321URI parses a ZIP-321 zcash: URI into its component parts.
// Returns an empty Zip321Parts if the URI is not a valid zcash: URI.
func ParseZip321URI(uri string) Zip321Parts {
	// Must start with "zcash:"
	if !strings.HasPrefix(uri, "zcash:") {
		return Zip321Parts{}
	}

	// Split off the "zcash:" prefix
	rest := strings.TrimPrefix(uri, "zcash:")

	// Split address from query params
	var address, queryStr string
	if idx := strings.Index(rest, "?"); idx >= 0 {
		address = rest[:idx]
		queryStr = rest[idx+1:]
	} else {
		address = rest
		return Zip321Parts{Address: address}
	}

	params, err := url.ParseQuery(queryStr)
	if err != nil {
		return Zip321Parts{Address: address}
	}

	amount := params.Get("amount")
	memoRaw := params.Get("memo")
	memoDecoded := DecodeBase64URL(memoRaw)

	return Zip321Parts{
		Address:     address,
		Amount:      amount,
		MemoRaw:     memoRaw,
		MemoDecoded: memoDecoded,
	}
}
