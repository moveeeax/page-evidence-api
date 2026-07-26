package rfc3161

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// DefaultTSA is a public, free RFC 3161 authority. It needs no account and no
// API key, which is what makes an evidence bundle reproducible by the
// recipient rather than dependent on us.
const DefaultTSA = "https://freetsa.org/tsr"

// FallbackTSA is used when the default one is unreachable.
const FallbackTSA = "http://timestamp.digicert.com"

// Client requests timestamps over HTTP.
type Client struct {
	HTTP    *http.Client
	Timeout time.Duration
}

// Stamp asks the TSA at url to timestamp digest and returns the raw DER
// TimeStampResp along with the nonce that was sent, so the caller can bind the
// response to its own request.
func (c *Client) Stamp(ctx context.Context, url string, digest []byte, opts RequestOptions) ([]byte, *big.Int, error) {
	reqDER, nonce, err := BuildRequest(digest, opts)
	if err != nil {
		return nil, nil, err
	}

	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp request to %s: %w", url, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp response from %s: %w", url, err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("timestamp request to %s: HTTP %d", url, httpResp.StatusCode)
	}

	resp, err := ParseResponse(body)
	if err != nil {
		return nil, nil, err
	}
	if !resp.Granted() {
		return nil, nil, fmt.Errorf("TSA %s refused the request: %s %v", url, StatusText(resp.Status), resp.StatusString)
	}
	return body, nonce, nil
}
