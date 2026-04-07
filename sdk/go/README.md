# ZNS Go SDK

Go client library for the Zcash Name System (ZNS) JSON-RPC API.

## Installation

```bash
go get github.com/zcashme/zns-sdk-go
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	zns "github.com/zcashme/zns-sdk-go"
)

func main() {
	// Create a client (verifies server UIVK by default)
	client, err := zns.NewClient(zns.DefaultURL)
	if err != nil {
		log.Fatal(err)
	}

	// Check server status
	status, err := client.Status()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Synced to height %d, %d names registered\n", status.SyncedHeight, status.Registered)

	// Resolve a name
	result, err := client.ResolveName("alice")
	if err != nil {
		log.Fatal(err)
	}
	if result != nil {
		fmt.Printf("alice -> %s\n", result.Address)
	} else {
		fmt.Println("alice is available!")
	}

	// Check availability
	available, err := client.IsAvailable("bob")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("bob available: %v\n", available)

	// Validate a name
	fmt.Println(zns.IsValidName("my-name"))  // true
	fmt.Println(zns.IsValidName("my--name")) // false

	// Calculate claim cost
	if status.Pricing != nil {
		cost := zns.ClaimCost(status.Pricing.Tiers, 5)
		if cost != nil {
			fmt.Printf("Cost for 5-char name: %d zatoshis\n", *cost)
		}
	}

	// Build a claim memo
	memo, err := zns.BuildClaimMemo("alice", "u1addr...", "sig...")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(memo)

	// Build a ZIP-321 payment URI
	uri := zns.BuildZcashURI("u1addr...", "0.001", memo)
	fmt.Println(uri)

	// Parse a ZIP-321 URI
	parts := zns.ParseZip321URI(uri)
	fmt.Printf("Address: %s, Memo: %s\n", parts.Address, parts.MemoDecoded)
}
```

## API Reference

### Client

- `NewClient(url string, opts ...ClientOptions) (*Client, error)` - Create a new client
- `client.Status() (*StatusResult, error)` - Get indexer status
- `client.Resolve(query string) (json.RawMessage, error)` - Raw resolve
- `client.ResolveName(name string) (*ResolveResult, error)` - Resolve a single name
- `client.ResolveAddress(addr string) ([]ResolveResult, error)` - Resolve by address
- `client.Listings() ([]Listing, error)` - Get all listings
- `client.Events(filter EventsFilter) (*EventsResult, error)` - Query events
- `client.IsAvailable(name string) (bool, error)` - Check name availability
- `client.GetNonce(name string) (*int, error)` - Get name nonce

### Utilities

- `IsValidName(name string) bool` - Validate a ZNS name
- `ClaimCost(tiers []int, nameLength int) *int` - Calculate claim cost

### Signing Payloads

- `ClaimPayload(name, ua string) string`
- `BuyPayload(name, buyerUA string) string`
- `ListPayload(name string, price, nonce int) string`
- `DelistPayload(name string, nonce int) string`
- `UpdatePayload(name, newUA string, nonce int) string`
- `SetPricePayload(prices []int, nonce int) string`

### Memo Builders

- `BuildClaimMemo(name, ua, signature string) (string, error)`
- `BuildBuyMemo(name, buyerUA, signature string) (string, error)`
- `BuildListMemo(name string, price, nonce int, signature string) (string, error)`
- `BuildDelistMemo(name string, nonce int, signature string) (string, error)`
- `BuildUpdateMemo(name, newUA string, nonce int, signature string) (string, error)`
- `BuildSetPriceMemo(prices []int, nonce int, signature string) (string, error)`

### ZIP-321

- `ToBase64URL(text string) string`
- `DecodeBase64URL(value string) string`
- `BuildZcashURI(address, amount, memo string) string`
- `ParseZip321URI(uri string) Zip321Parts`
