package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/ioc"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store, httpx.New())
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestIOCsCreateAndList(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"type": "IP", "value": "203.0.113.5", "confidence": 90, "severity": "Critical", "source": "manual",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/iocs", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created ioc.Indicator
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created IOC: %v", err)
	}
	if created.Value != "203.0.113.5" || created.Severity != "Critical" {
		t.Errorf("unexpected created IOC: %#v", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/intel/iocs?type=IP", nil)
	listRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listRec.Code)
	}
	var listBody struct {
		IOCs  []ioc.Indicator `json:"iocs"`
		Total int             `json:"total"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listBody.Total != 1 || len(listBody.IOCs) != 1 {
		t.Errorf("expected 1 IOC in list, got total=%d items=%d", listBody.Total, len(listBody.IOCs))
	}
}

func TestIOCsCreateRequiresTypeAndValue(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/iocs", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestOsintIPRequiresParam(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/osint/ip", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAnalyzeWithInlineContent(t *testing.T) {
	s := newTestServer(t)

	// Seed a known-bad IP via the create endpoint, then analyze content containing it.
	iocBody, _ := json.Marshal(map[string]any{"type": "IP", "value": "198.51.100.7", "confidence": 90, "severity": "High", "source": "manual"})
	req := httptest.NewRequest(http.MethodPost, "/v1/intel/iocs", bytes.NewReader(iocBody))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed IOC failed: %d", rec.Code)
	}

	analyzeBody, _ := json.Marshal(map[string]string{"content": "connection from 198.51.100.7 refused\nclean line\n"})
	analyzeReq := httptest.NewRequest(http.MethodPost, "/v1/analyze", bytes.NewReader(analyzeBody))
	analyzeRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(analyzeRec, analyzeReq)
	if analyzeRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", analyzeRec.Code, analyzeRec.Body.String())
	}
	var result struct {
		Hits []any `json:"hits"`
	}
	if err := json.Unmarshal(analyzeRec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode analyze result: %v", err)
	}
	if len(result.Hits) != 1 {
		t.Errorf("expected 1 hit, got %d", len(result.Hits))
	}
}
