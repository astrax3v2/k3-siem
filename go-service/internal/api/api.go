// Package api is the Go service's internal HTTP surface — not meant to be exposed publicly.
// Node's existing routes (backend/src/routes/osint.js, the intel/* routes in
// backend/src/routes/api.js, and events.js's /import) become thin proxies to these endpoints
// in Phase 3b, so response shapes here deliberately stay close to what Node already returns.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"k3siem/goservice/internal/analyzer"
	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/feeds"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/ioc"
	"k3siem/goservice/internal/osint"
	"k3siem/goservice/internal/report"
)

// Server holds the shared dependencies every handler needs.
type Server struct {
	store  *cache.Store
	client *httpx.Client
	mux    *http.ServeMux
}

// New builds a Server and registers all routes.
func New(store *cache.Store, client *httpx.Client) *Server {
	s := &Server{store: store, client: client, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the http.Handler to mount (e.g. via http.ListenAndServe).
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	s.mux.HandleFunc("GET /v1/osint/ip", s.handleOsintIP)
	s.mux.HandleFunc("GET /v1/osint/domain", s.handleOsintDomain)
	s.mux.HandleFunc("GET /v1/osint/hash", s.handleOsintHash)
	s.mux.HandleFunc("GET /v1/osint/email", s.handleOsintEmail)

	s.mux.HandleFunc("GET /v1/intel/feeds", s.handleFeedsList)
	s.mux.HandleFunc("POST /v1/intel/feeds/sync", s.handleFeedsSync)
	s.mux.HandleFunc("GET /v1/intel/iocs", s.handleIOCsList)
	s.mux.HandleFunc("POST /v1/intel/iocs", s.handleIOCsCreate)

	s.mux.HandleFunc("POST /v1/analyze", s.handleAnalyze)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- OSINT ---------------------------------------------------------------

func (s *Server) handleOsintIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	writeJSON(w, http.StatusOK, osint.LookupIP(r.Context(), s.client, s.store, ip, osint.DefaultTTL))
}

func (s *Server) handleOsintDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	writeJSON(w, http.StatusOK, osint.LookupDomain(r.Context(), s.client, s.store, domain, osint.DefaultTTL))
}

func (s *Server) handleOsintHash(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "hash is required")
		return
	}
	writeJSON(w, http.StatusOK, osint.LookupHash(r.Context(), s.client, s.store, hash, osint.DefaultTTL))
}

func (s *Server) handleOsintEmail(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	writeJSON(w, http.StatusOK, osint.LookupEmail(r.Context(), s.client, s.store, email, osint.DefaultTTL))
}

// --- Threat intel: feeds ---------------------------------------------------

func (s *Server) handleFeedsList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListFeedMeta()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": list})
}

func (s *Server) handleFeedsSync(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "true"
	summary, err := feeds.SyncAll(r.Context(), s.store, s.client, force)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// --- Threat intel: IOCs -----------------------------------------------------

func (s *Server) handleIOCsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	result, err := s.store.ListIOCs(cache.IOCFilter{
		Type: q.Get("type"), Severity: q.Get("severity"), Search: q.Get("search"),
		Page: page, Limit: limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"iocs": result.Items, "total": result.Total, "pages": result.Pages})
}

func (s *Server) handleIOCsCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type        string   `json:"type"`
		Value       string   `json:"value"`
		Confidence  int      `json:"confidence"`
		Severity    string   `json:"severity"`
		Source      string   `json:"source"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Type == "" || body.Value == "" {
		writeError(w, http.StatusBadRequest, "type and value required")
		return
	}
	confidence := body.Confidence
	if confidence == 0 {
		confidence = 50
	}
	severity := body.Severity
	if severity == "" {
		severity = "Medium"
	}
	ind := ioc.Indicator{
		Type: ioc.Type(body.Type), Value: body.Value, Confidence: confidence,
		Severity: severity, Source: body.Source, Description: body.Description,
	}
	if _, err := s.store.UpsertBatch([]ioc.Indicator{ind}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	created, found, err := s.store.GetIOC(ind.Type, ind.Value)
	if err != nil || !found {
		writeError(w, http.StatusInternalServerError, "failed to read back created IOC")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// --- Offline log analysis ---------------------------------------------------

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content  string `json:"content"`
		FilePath string `json:"file_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	path := body.FilePath
	if path == "" {
		if body.Content == "" {
			writeError(w, http.StatusBadRequest, "content or file_path is required")
			return
		}
		tmp, err := os.CreateTemp("", "k3-analyze-*.log")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(body.Content); err != nil {
			tmp.Close()
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		tmp.Close()
		path = tmp.Name()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	result, err := analyzer.Analyze(ctx, s.store, path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if r.URL.Query().Get("format") == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = report.RenderHTML(w, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
