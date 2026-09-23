// Package analyzer is the offline log analyzer: it streams a log file line-by-line, parses
// each line via internal/ocsf for structured fields (src/dst IP, user, computer) alongside the
// same regex candidate families as backend/src/services/iocMatcher.js for value types OCSF
// doesn't extract (hash/url/domain/email), matches everything against the disk-backed IOC
// cache, and enriches any IP/domain hit with whatever OSINT data is already cached for it.
// Everything here is pure CPU + cache reads (no network), so it runs fully offline once the
// cache has been populated by `feeds.SyncAll` / `osint.Lookup*`.
package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/imagemeta"
	"k3siem/goservice/internal/ioc"
	"k3siem/goservice/internal/ocsf"
	"k3siem/goservice/internal/osint"
)

const maxCandidatesPerType = 25

var (
	ipv4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hashRe   = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b`)
	urlRe    = regexp.MustCompile(`https?://[^\s"'<>]+`)
	domainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`)
	emailRe  = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
)

// candidateSet holds the deduped, capped candidate values extracted from one log line, mirroring
// the `{IP, Hash, URL, Domain, Email}` shape of the Node extractCandidates() return value.
type candidateSet struct {
	IP     []string
	Hash   []string
	URL    []string
	Domain []string
	Email  []string
}

// extractCandidates finds IOC candidates in a single line of raw log text plus whatever OCSF
// already extracted structurally (src_endpoint/dst_endpoint IPs) — merged and deduped into the
// same IP bucket, since OCSF's field-aware extraction catches cases the bare IPv4 regex alone
// would miss context for (e.g. distinguishing src vs dst) while the regex still catches IPs in
// vendor-specific text OCSF's normalizers don't map to a field. Domains that were already
// captured as part of an email address are skipped, matching the Node logic
// (`if (!out.Email.has(m)) out.Domain.add(m)`).
func extractCandidates(rec ocsf.Record, line string) candidateSet {
	var out candidateSet
	ipSeen, hashSeen, urlSeen, domainSeen, emailSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}

	addIP := func(v string) {
		if v == "" || len(out.IP) >= maxCandidatesPerType || ipSeen[v] || net.ParseIP(v) == nil {
			return
		}
		ipSeen[v] = true
		out.IP = append(out.IP, v)
	}
	addIP(rec.IPAddress)
	addIP(rec.DstIPAddress)
	for _, m := range ipv4Re.FindAllString(line, -1) {
		addIP(m)
	}

	for _, m := range hashRe.FindAllString(line, -1) {
		v := strings.ToLower(m)
		if len(out.Hash) >= maxCandidatesPerType {
			break
		}
		if hashSeen[v] {
			continue
		}
		hashSeen[v] = true
		out.Hash = append(out.Hash, v)
	}
	for _, m := range urlRe.FindAllString(line, -1) {
		if len(out.URL) >= maxCandidatesPerType {
			break
		}
		if urlSeen[m] {
			continue
		}
		urlSeen[m] = true
		out.URL = append(out.URL, m)
	}
	for _, m := range emailRe.FindAllString(line, -1) {
		v := strings.ToLower(m)
		if len(out.Email) >= maxCandidatesPerType {
			break
		}
		if emailSeen[v] {
			continue
		}
		emailSeen[v] = true
		out.Email = append(out.Email, v)
	}
	for _, m := range domainRe.FindAllString(line, -1) {
		v := strings.ToLower(m)
		if emailSeen[v] {
			continue
		}
		if len(out.Domain) >= maxCandidatesPerType {
			break
		}
		if domainSeen[v] {
			continue
		}
		domainSeen[v] = true
		out.Domain = append(out.Domain, v)
	}
	return out
}

// Hit is one IOC match found while scanning the input.
type Hit struct {
	SourceFile string        `json:"source_file,omitempty"` // set when the input was a directory of multiple files
	LineNumber int           `json:"line_number"`
	Excerpt    string        `json:"excerpt"`
	MatchType  string        `json:"match_type"` // exact | cidr
	Indicator  ioc.Indicator `json:"indicator"`
	OSINT      *osint.Result `json:"osint,omitempty"`
}

// osintKind maps an ioc.Type onto the cache-key prefix osint.Lookup* uses, for the two types
// OSINT enrichment applies to; other types (Hash/URL/Email) have no cached-lookup analogue
// wired up yet.
func osintKind(t ioc.Type) (string, bool) {
	switch t {
	case ioc.TypeIP:
		return "ip", true
	case ioc.TypeDomain:
		return "domain", true
	case ioc.TypeURL:
		return "url", true
	default:
		return "", false
	}
}

// Result is the full outcome of one Analyze() run.
type Result struct {
	Input          string             `json:"input"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at"`
	LinesScanned   int                `json:"lines_scanned"`
	FilesScanned   int                `json:"files_scanned,omitempty"` // set when the input was a directory
	Hits           []Hit              `json:"hits"`
	HitsBySeverity map[string]int     `json:"hits_by_severity"`
	Images         []imagemeta.Result `json:"images,omitempty"` // evidence images found alongside/instead of logs
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// matchLine parses one line via OCSF, checks its candidates against the cache, and enriches
// any IP/domain hit with whatever OSINT data is already cached for it — no live OSINT lookups
// happen here, only cache.Store reads, so this stays fully offline. A single indicator is
// reported at most once per line even if it's found via more than one candidate type (e.g. an
// IP appearing both literally and inside a CIDR range).
func matchLine(store *cache.Store, lineNumber int, text string) []Hit {
	rec := ocsf.ParseLogRecord(text)
	candidates := extractCandidates(rec, text)
	seen := map[string]bool{}
	var hits []Hit

	report := func(ind ioc.Indicator, matchType string) {
		if seen[ind.ID] {
			return
		}
		seen[ind.ID] = true
		_ = store.IncrementHit(ind.Type, ind.Value)
		hit := Hit{LineNumber: lineNumber, Excerpt: truncate(text, 240), MatchType: matchType, Indicator: ind}
		if kind, ok := osintKind(ind.Type); ok {
			if cached, found := osint.GetCachedOnly(store, kind, ind.Value); found {
				hit.OSINT = &cached
			}
		}
		hits = append(hits, hit)
	}

	groups := []struct {
		t      ioc.Type
		values []string
	}{
		{ioc.TypeIP, candidates.IP},
		{ioc.TypeHash, candidates.Hash},
		{ioc.TypeURL, candidates.URL},
		{ioc.TypeDomain, candidates.Domain},
		{ioc.TypeEmail, candidates.Email},
	}
	for _, group := range groups {
		if len(group.values) == 0 {
			continue
		}
		found, err := store.MatchByTypeValues(group.t, group.values)
		if err != nil {
			continue
		}
		for _, ind := range found {
			report(ind, "exact")
		}
	}

	if len(candidates.IP) > 0 {
		if cidrHits, err := store.MatchCIDR(candidates.IP); err == nil {
			for _, ind := range cidrHits {
				report(ind, "cidr")
			}
		}
	}
	return hits
}

// Analyze is the entrypoint: path may be a single log file, a single image, or a directory
// containing any mix of both — the whole point of an evidence set in a forensic investigation
// is that it's rarely just one file. Log files are matched against the IOC cache as before;
// image files (per imagemeta.SupportedExt) get read-only EXIF/IPTC/XMP metadata extraction
// instead, and their results land in Result.Images rather than Result.Hits.
func Analyze(ctx context.Context, store *cache.Store, path string) (Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Result{Input: path}, err
	}
	if info.IsDir() {
		return analyzeDir(ctx, store, path)
	}
	if imagemeta.SupportedExt(path) {
		return analyzeSingleImage(path), nil
	}
	return analyzeLogFile(ctx, store, path)
}

// analyzeSingleImage wraps one image's metadata extraction in a Result — no log-side fields
// apply (LinesScanned stays 0, Hits stays empty).
func analyzeSingleImage(path string) Result {
	result := Result{Input: path, StartedAt: time.Now().UTC(), HitsBySeverity: map[string]int{}}
	img, err := imagemeta.Extract(path)
	if err != nil {
		img = imagemeta.Result{Path: path, Warning: err.Error()}
	}
	result.Images = append(result.Images, img)
	result.FinishedAt = time.Now().UTC()
	return result
}

// analyzeDir walks an evidence directory, routing each file to either image-metadata
// extraction or log analysis based on its extension, and aggregates both into one Result.
// A single unreadable/corrupt file is skipped (recorded as a Warning on its own image entry,
// or simply not counted for logs) rather than aborting analysis of the rest of the evidence.
func analyzeDir(ctx context.Context, store *cache.Store, dirPath string) (Result, error) {
	result := Result{Input: dirPath, StartedAt: time.Now().UTC(), HitsBySeverity: map[string]int{}}

	walkErr := filepath.WalkDir(dirPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if imagemeta.SupportedExt(p) {
			img, extractErr := imagemeta.Extract(p)
			if extractErr != nil {
				img = imagemeta.Result{Path: p, Warning: extractErr.Error()}
			}
			result.Images = append(result.Images, img)
			return nil
		}
		if looksBinary(p) {
			// Real evidence directories routinely contain PDFs, Office docs, archives, the
			// analyzer's own cache.db, etc. alongside logs and images — scanning those as text
			// wastes time and can spuriously match IOC regexes against arbitrary bytes.
			return nil
		}

		sub, subErr := analyzeLogFile(ctx, store, p)
		if subErr != nil {
			return nil // unreadable/binary file in the evidence set — skip, don't abort the batch
		}
		result.FilesScanned++
		result.LinesScanned += sub.LinesScanned
		result.Hits = append(result.Hits, sub.Hits...)
		for sev, count := range sub.HitsBySeverity {
			result.HitsBySeverity[sev] += count
		}
		return nil
	})

	result.FinishedAt = time.Now().UTC()
	sort.Slice(result.Hits, func(i, j int) bool {
		if result.Hits[i].SourceFile != result.Hits[j].SourceFile {
			return result.Hits[i].SourceFile < result.Hits[j].SourceFile
		}
		return result.Hits[i].LineNumber < result.Hits[j].LineNumber
	})
	return result, walkErr
}

// looksBinary sniffs the first bytes of the file at path for a NUL byte — the same heuristic
// git and most other tools use to distinguish text from binary content. A read failure is not
// this function's concern (analyzeLogFile will surface it as a real error), so it just reports
// false and lets the caller proceed to the normal open/scan path.
func looksBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8000)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) != -1
}

// analyzeLogFile streams the file at path line-by-line, matching each line's IOC candidates
// against store using a runtime.NumCPU()-sized worker pool. Memory stays flat regardless of
// file size: the input is never read into memory as a whole, only one line (plus bounded
// queues) is held per in-flight worker at a time.
func analyzeLogFile(ctx context.Context, store *cache.Store, path string) (Result, error) {
	result := Result{Input: path, StartedAt: time.Now().UTC(), HitsBySeverity: map[string]int{}}

	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	type lineTask struct {
		Number int
		Text   string
	}

	workerCount := runtime.NumCPU()
	lines := make(chan lineTask, workerCount*4)
	hitsCh := make(chan Hit, workerCount*4)

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for task := range lines {
				for _, hit := range matchLine(store, task.Number, task.Text) {
					hitsCh <- hit
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for hit := range hitsCh {
			hit.SourceFile = path
			result.Hits = append(result.Hits, hit)
			result.HitsBySeverity[hit.Indicator.Severity]++
		}
	}()

	lineNo := 0
readLoop:
	for scanner.Scan() {
		lineNo++
		select {
		case <-ctx.Done():
			break readLoop
		case lines <- lineTask{Number: lineNo, Text: scanner.Text()}:
		}
	}
	close(lines)
	wg.Wait()
	close(hitsCh)
	<-done

	result.LinesScanned = lineNo
	result.FinishedAt = time.Now().UTC()
	sort.Slice(result.Hits, func(i, j int) bool { return result.Hits[i].LineNumber < result.Hits[j].LineNumber })

	if err := scanner.Err(); err != nil {
		return result, err
	}
	return result, ctx.Err()
}
