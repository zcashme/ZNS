package zns

import (
	"fmt"
	"strconv"
	"strings"
)

// --- Signing Payloads ---

// ClaimPayload returns the signing payload for a CLAIM action.
func ClaimPayload(name, ua string) string {
	return fmt.Sprintf("CLAIM:%s:%s", name, ua)
}

// BuyPayload returns the signing payload for a BUY action.
func BuyPayload(name, buyerUA string) string {
	return fmt.Sprintf("BUY:%s:%s", name, buyerUA)
}

// ListPayload returns the signing payload for a LIST action.
func ListPayload(name string, price, nonce int) string {
	return fmt.Sprintf("LIST:%s:%d:%d", name, price, nonce)
}

// DelistPayload returns the signing payload for a DELIST action.
func DelistPayload(name string, nonce int) string {
	return fmt.Sprintf("DELIST:%s:%d", name, nonce)
}

// UpdatePayload returns the signing payload for an UPDATE action.
func UpdatePayload(name, newUA string, nonce int) string {
	return fmt.Sprintf("UPDATE:%s:%s:%d", name, newUA, nonce)
}

// SetPricePayload returns the signing payload for a SETPRICE action.
func SetPricePayload(prices []int, nonce int) string {
	parts := make([]string, len(prices))
	for i, p := range prices {
		parts[i] = strconv.Itoa(p)
	}
	return fmt.Sprintf("SETPRICE:%d:%s:%d", len(prices), strings.Join(parts, ":"), nonce)
}

// --- Memo Builders ---

// BuildClaimMemo builds a ZNS CLAIM memo string.
func BuildClaimMemo(name, ua, signature string) (string, error) {
	if !IsValidName(name) {
		return "", &ZNSError{Code: InvalidParams, Message: fmt.Sprintf("invalid name: %q", name)}
	}
	return fmt.Sprintf("ZNS:CLAIM:%s:%s:%s", name, ua, signature), nil
}

// BuildBuyMemo builds a ZNS BUY memo string.
func BuildBuyMemo(name, buyerUA, signature string) (string, error) {
	if !IsValidName(name) {
		return "", &ZNSError{Code: InvalidParams, Message: fmt.Sprintf("invalid name: %q", name)}
	}
	return fmt.Sprintf("ZNS:BUY:%s:%s:%s", name, buyerUA, signature), nil
}

// BuildListMemo builds a ZNS LIST memo string.
func BuildListMemo(name string, price, nonce int, signature string) (string, error) {
	if !IsValidName(name) {
		return "", &ZNSError{Code: InvalidParams, Message: fmt.Sprintf("invalid name: %q", name)}
	}
	return fmt.Sprintf("ZNS:LIST:%s:%d:%d:%s", name, price, nonce, signature), nil
}

// BuildDelistMemo builds a ZNS DELIST memo string.
func BuildDelistMemo(name string, nonce int, signature string) (string, error) {
	if !IsValidName(name) {
		return "", &ZNSError{Code: InvalidParams, Message: fmt.Sprintf("invalid name: %q", name)}
	}
	return fmt.Sprintf("ZNS:DELIST:%s:%d:%s", name, nonce, signature), nil
}

// BuildUpdateMemo builds a ZNS UPDATE memo string.
func BuildUpdateMemo(name, newUA string, nonce int, signature string) (string, error) {
	if !IsValidName(name) {
		return "", &ZNSError{Code: InvalidParams, Message: fmt.Sprintf("invalid name: %q", name)}
	}
	return fmt.Sprintf("ZNS:UPDATE:%s:%s:%d:%s", name, newUA, nonce, signature), nil
}

// BuildSetPriceMemo builds a ZNS SETPRICE memo string.
func BuildSetPriceMemo(prices []int, nonce int, signature string) (string, error) {
	parts := make([]string, len(prices))
	for i, p := range prices {
		parts[i] = strconv.Itoa(p)
	}
	return fmt.Sprintf("ZNS:SETPRICE:%d:%s:%d:%s", len(prices), strings.Join(parts, ":"), nonce, signature), nil
}
