package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostJSONSendsBodyAndDecodesResponse(t *testing.T) {
	var gotBody map[string]any
	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("server failed to decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches": ["ok"]}`))
	}))
	defer server.Close()

	client := New()
	var out struct {
		Matches []string `json:"matches"`
	}
	err := client.PostJSON(context.Background(), server.URL, FetchOptions{}, map[string]string{"hello": "world"}, &out)
	if err != nil {
		t.Fatalf("PostJSON: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", gotContentType)
	}
	if gotBody["hello"] != "world" {
		t.Errorf("expected request body to be sent, got %#v", gotBody)
	}
	if len(out.Matches) != 1 || out.Matches[0] != "ok" {
		t.Errorf("expected decoded response matches=[ok], got %#v", out.Matches)
	}
}

func TestPostJSONNonSuccessStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := New()
	var out any
	if err := client.PostJSON(context.Background(), server.URL, FetchOptions{}, map[string]string{}, &out); err == nil {
		t.Error("expected an error for a non-2xx response")
	}
}
