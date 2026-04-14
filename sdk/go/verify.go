package zns

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// VerifySignature checks an Ed25519 signature against a base64-encoded public key.
func VerifySignature(payload, signatureB64, pubkeyB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	pk, err := base64.StdEncoding.DecodeString(pubkeyB64)
	if err != nil || len(pk) != 32 {
		return false
	}
	return ed25519.Verify(pk, []byte(payload), sig)
}

// RegistrationPayload reconstructs the signing pre-image from a Registration.
func RegistrationPayload(reg Registration) string {
	switch reg.LastAction {
	case "CLAIM":
		return fmt.Sprintf("CLAIM:%s:%s", reg.Name, reg.Address)
	case "BUY":
		return fmt.Sprintf("BUY:%s:%s", reg.Name, reg.Address)
	case "UPDATE":
		return fmt.Sprintf("UPDATE:%s:%s:%d", reg.Name, reg.Address, reg.Nonce)
	case "DELIST":
		return fmt.Sprintf("DELIST:%s:%d", reg.Name, reg.Nonce)
	case "RELEASE":
		return fmt.Sprintf("RELEASE:%s:%d", reg.Name, reg.Nonce)
	default:
		return ""
	}
}

// ListingPayload reconstructs the signing pre-image from a Listing.
func ListingPayload(listing Listing) string {
	return fmt.Sprintf("LIST:%s:%d:%d", listing.Name, listing.Price, listing.Nonce)
}

// VerifyRegistration verifies a Registration's signature.
// If reg.Pubkey is set, verifies against the sovereign user key;
// otherwise verifies against the admin pubkey.
func VerifyRegistration(reg Registration, adminPubkey string) bool {
	sig := reg.Signature
	if sig == nil || *sig == "" {
		return false
	}
	payload := RegistrationPayload(reg)
	if payload == "" {
		return false
	}
	pubkey := adminPubkey
	if reg.Pubkey != nil && *reg.Pubkey != "" {
		pubkey = *reg.Pubkey
	}
	return VerifySignature(payload, *sig, pubkey)
}

// VerifyListing verifies a Listing's signature against the admin pubkey.
func VerifyListing(listing Listing, adminPubkey string) bool {
	payload := ListingPayload(listing)
	return VerifySignature(payload, listing.Signature, adminPubkey)
}
