// Package httpx is the shared HTTP client used by feed sync and (later) OSINT lookups —
// one configured client/transport instead of each source rolling its own, plus small
// context-aware fetch helpers mirroring the Node `fetchText`/`fetchJson` helpers in
// backend/src/services/connectors/feedSync.js.
package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client wraps a single *http.Client tuned for outbound feed/OSINT fetches: bounded idle
// connections and a dial/TLS timeout, independent of the per-request context timeout callers
// set via FetchText/FetchJSON.
type Client struct {
	http *http.Client
}

// New returns a Client ready for use. A single instance should be shared across all fetches
// so connections are pooled instead of re-established per request.
func New() *Client {
	return &Client{
		http: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// FetchOptions customizes a single fetch call.
type FetchOptions struct {
	Headers   map[string]string
	TimeoutMs int // defaults to 30000, matching the Node default
}

func (o FetchOptions) timeout() time.Duration {
	if o.TimeoutMs <= 0 {
		return 30 * time.Second
	}
	return time.Duration(o.TimeoutMs) * time.Millisecond
}

func (c *Client) do(ctx context.Context, url string, opts FetchOptions) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	res, err := c.http.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	// The response body must be read (and closed) before the timeout context is released;
	// wrap the body so cancel() fires only once the caller is done reading it.
	res.Body = &cancelOnCloseBody{ReadCloser: res.Body, cancel: cancel}
	return res, nil
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	defer b.cancel()
	return b.ReadCloser.Close()
}

// FetchText GETs url and returns the raw response body, erroring on any non-2xx status —
// mirrors the Node fetchText() helper.
func (c *Client) FetchText(ctx context.Context, url string, opts FetchOptions) (string, error) {
	res, err := c.do(ctx, url, opts)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FetchJSON GETs url and decodes the JSON body into out — mirrors the Node fetchJson() helper.
func (c *Client) FetchJSON(ctx context.Context, url string, opts FetchOptions, out any) error {
	res, err := c.do(ctx, url, opts)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(out)
}
