// Package zns provides a Go SDK for the Zcash Name System (ZNS) JSON-RPC API.
package zns

import "fmt"

// DefaultURL is the default ZNS JSON-RPC endpoint.
const DefaultURL = "https://light.zcash.me/zns-testnet"

// TestnetUIVK is the Unified Incoming Viewing Key for the ZNS testnet.
const TestnetUIVK = "uivktest1hzw7wyadutvzfgpna80yftsk5l7jeyu2p5me5quvp28tytxueta00cx4068wnlzcv7tx9n3t3gfhsy83pe4y6jrhxtzaq0hj6xtg5zrk2dn7zen3vns2a5pgs4fxdjlletmqrhfa42"

// MainnetUIVK is the Unified Incoming Viewing Key for the ZNS mainnet.
const MainnetUIVK = "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6"

// KnownUIVKs is the list of known UIVKs used for server verification.
var KnownUIVKs = []string{TestnetUIVK, MainnetUIVK}

// Standard JSON-RPC error codes.
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// Custom SDK error codes.
const (
	ErrHTTP         = -1
	ErrUIVKMismatch = -2
)

// ZNSError represents an error returned by the ZNS JSON-RPC API or the SDK itself.
type ZNSError struct {
	Code    int
	Message string
}

// Error implements the error interface.
func (e *ZNSError) Error() string {
	return fmt.Sprintf("ZNS error %d: %s", e.Code, e.Message)
}

// Registration represents a registered ZNS name.
type Registration struct {
	Name       string  `json:"name"`
	Address    string  `json:"address"`
	Txid       string  `json:"txid"`
	Height     int     `json:"height"`
	Nonce      int     `json:"nonce"`
	Signature  *string `json:"signature"`
	LastAction string  `json:"last_action"`
	Pubkey     *string `json:"pubkey"`
}

// Listing represents a name listed for sale.
type Listing struct {
	Name      string `json:"name"`
	Price     int    `json:"price"`
	Nonce     int    `json:"nonce"`
	Txid      string `json:"txid"`
	Height    int    `json:"height"`
	Signature string `json:"signature"`
}

// ResolveResult represents the result of resolving a ZNS name or address.
type ResolveResult struct {
	Registration
	Listing *Listing `json:"listing"`
}

// Pricing represents the current pricing tiers and nonce for name claims.
type Pricing struct {
	Nonce  int   `json:"nonce"`
	Height int   `json:"height"`
	Tiers  []int `json:"tiers"`
}

// StatusResult represents the status of the ZNS indexer.
type StatusResult struct {
	SyncedHeight int      `json:"synced_height"`
	AdminPubkey  string   `json:"admin_pubkey"`
	UIVK         string   `json:"uivk"`
	Address      string   `json:"address"`
	Registered   int      `json:"registered"`
	Listed       int      `json:"listed"`
	Pricing      *Pricing `json:"pricing"`
}

// Event represents a ZNS event from the event log.
type Event struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Action    string  `json:"action"`
	Txid      string  `json:"txid"`
	Height    int     `json:"height"`
	UA        *string `json:"ua"`
	Price     *int    `json:"price"`
	Nonce     *int    `json:"nonce"`
	Signature *string `json:"signature"`
	Pubkey    *string `json:"pubkey"`
}

// EventsFilter specifies optional filters for querying events.
type EventsFilter struct {
	Name        string `json:"name,omitempty"`
	Action      string `json:"action,omitempty"`
	SinceHeight int    `json:"since_height,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Offset      int    `json:"offset,omitempty"`
}

// EventsResult contains a page of events and the total count.
type EventsResult struct {
	Events []Event `json:"events"`
	Total  int     `json:"total"`
}
