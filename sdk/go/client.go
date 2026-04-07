package zns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// rpcRequest is the JSON-RPC 2.0 request envelope.
type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// rpcResponse is the JSON-RPC 2.0 response envelope.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is the JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ClientOptions configures the ZNS client.
type ClientOptions struct {
	// SkipVerify disables UIVK verification against KnownUIVKs during construction.
	SkipVerify bool
}

// Client is a ZNS JSON-RPC client.
type Client struct {
	// URL is the JSON-RPC endpoint URL.
	URL string
	// Verified indicates whether the server UIVK was verified against KnownUIVKs.
	Verified bool

	mu     sync.Mutex
	id     int
	client *http.Client
}

// NewClient creates a new ZNS client. It calls Status() to verify the server
// and checks that the returned UIVK is in KnownUIVKs (unless SkipVerify is set).
func NewClient(url string, opts ...ClientOptions) (*Client, error) {
	skipVerify := false
	if len(opts) > 0 {
		skipVerify = opts[0].SkipVerify
	}

	c := &Client{
		URL:    url,
		client: &http.Client{},
	}

	status, err := c.Status()
	if err != nil {
		return nil, err
	}

	if !skipVerify {
		found := false
		for _, known := range KnownUIVKs {
			if status.UIVK == known {
				found = true
				break
			}
		}
		if !found {
			return nil, &ZNSError{
				Code:    ErrUIVKMismatch,
				Message: fmt.Sprintf("server UIVK %q does not match any known UIVK", status.UIVK),
			}
		}
		c.Verified = true
	}

	return c, nil
}

// nextID returns a monotonically increasing request ID.
func (c *Client) nextID() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.id++
	return c.id
}

// call performs a JSON-RPC 2.0 call and returns the raw result.
func (c *Client) call(method string, params interface{}) (json.RawMessage, error) {
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpResp, err := c.client.Post(c.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, &ZNSError{Code: ErrHTTP, Message: err.Error()}
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, &ZNSError{Code: ErrHTTP, Message: fmt.Sprintf("failed to read response: %s", err)}
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, &ZNSError{
			Code:    ErrHTTP,
			Message: fmt.Sprintf("HTTP %d: %s", httpResp.StatusCode, string(respBody)),
		}
	}

	var resp rpcResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, &ZNSError{Code: ParseError, Message: fmt.Sprintf("failed to parse response: %s", err)}
	}

	if resp.Error != nil {
		return nil, &ZNSError{Code: resp.Error.Code, Message: resp.Error.Message}
	}

	return resp.Result, nil
}

// Status returns the current status of the ZNS indexer.
func (c *Client) Status() (*StatusResult, error) {
	raw, err := c.call("status", nil)
	if err != nil {
		return nil, err
	}
	var result StatusResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal status result: %w", err)
	}
	return &result, nil
}

// Resolve performs a raw resolve query. The result can be a single ResolveResult,
// a slice of ResolveResult, or null depending on whether the query is a name or address.
// Use ResolveName or ResolveAddress for typed results.
func (c *Client) Resolve(query string) (json.RawMessage, error) {
	return c.call("resolve", []interface{}{query})
}

// ResolveName resolves a single ZNS name. Returns nil if the name is not registered.
func (c *Client) ResolveName(name string) (*ResolveResult, error) {
	raw, err := c.Resolve(name)
	if err != nil {
		return nil, err
	}

	// Check for JSON null
	if string(raw) == "null" {
		return nil, nil
	}

	var result ResolveResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resolve result: %w", err)
	}
	return &result, nil
}

// ResolveAddress resolves all names registered to an address.
func (c *Client) ResolveAddress(addr string) ([]ResolveResult, error) {
	raw, err := c.Resolve(addr)
	if err != nil {
		return nil, err
	}

	// Check for JSON null
	if string(raw) == "null" {
		return nil, nil
	}

	var results []ResolveResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resolve results: %w", err)
	}
	return results, nil
}

// Listings returns all names currently listed for sale.
func (c *Client) Listings() ([]Listing, error) {
	raw, err := c.call("listings", nil)
	if err != nil {
		return nil, err
	}
	var results []Listing
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal listings: %w", err)
	}
	return results, nil
}

// Events queries the event log with optional filters.
func (c *Client) Events(filter EventsFilter) (*EventsResult, error) {
	raw, err := c.call("events", []interface{}{filter})
	if err != nil {
		return nil, err
	}
	var result EventsResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal events result: %w", err)
	}
	return &result, nil
}

// IsAvailable checks whether a name is available for registration.
func (c *Client) IsAvailable(name string) (bool, error) {
	result, err := c.ResolveName(name)
	if err != nil {
		return false, err
	}
	return result == nil, nil
}

// GetNonce returns the current nonce for a registered name. Returns nil if the name
// is not registered.
func (c *Client) GetNonce(name string) (*int, error) {
	result, err := c.ResolveName(name)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	nonce := result.Nonce
	return &nonce, nil
}
