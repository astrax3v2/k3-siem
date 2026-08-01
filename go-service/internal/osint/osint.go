package osint

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/httpx"
)

// DefaultTTL matches the Node in-memory OSINT cache's 24h window — short enough that
// reputation data stays reasonably fresh, unlike the IOC feeds' 30-day cadence which is
// naturally per-feed rather than per-lookup-target.
const DefaultTTL = 24 * time.Hour

// SourceResult is one named source's outcome within a lookup, matching the Node
// `{configured, data}` shape exactly so a future Node proxy layer can pass this straight
// through unchanged.
type SourceResult struct {
	Configured bool `json:"configured"`
	Data       any  `json:"data"`
}

// Result is the full multi-source lookup outcome for one target, matching the Node
// `{target, type, sources}` response shape.
type Result struct {
	Target    string                  `json:"target"`
	Type      string                  `json:"type"` // ip | domain | hash | email
	Sources   map[string]SourceResult `json:"sources"`
	FetchedAt time.Time               `json:"fetched_at"`
	Stale     bool                    `json:"stale,omitempty"`
}

func cacheKey(kind, target string) string { return kind + ":" + target }

func getCached(store *cache.Store, key string, ttl time.Duration) (Result, bool) {
	if store == nil {
		return Result{}, false
	}
	data, found, err := store.GetOsintBlob(key)
	if err != nil || !found {
		return Result{}, false
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return Result{}, false
	}
	if ttl > 0 && time.Since(result.FetchedAt) > ttl {
		result.Stale = true
		return result, false // stale: caller should refetch, but the value is still returned to callers that want it (e.g. offline mode)
	}
	return result, true
}

func setCached(store *cache.Store, key string, result Result) {
	if store == nil {
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	_ = store.SetOsintBlob(key, data)
}

// GetCachedOnly returns whatever is cached for (kind, target) regardless of TTL staleness —
// used by the offline analyzer, which has no network access to refresh anything anyway and
// would rather show stale-but-real data than nothing.
func GetCachedOnly(store *cache.Store, kind, target string) (Result, bool) {
	data, found, err := store.GetOsintBlob(cacheKey(kind, target))
	if err != nil || !found {
		return Result{}, false
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return Result{}, false
	}
	return result, true
}

// sourceFunc runs one named source and reports its result; sources return (data, configured).
type sourceFunc func(ctx context.Context) (data any, configured bool)

// runSources fans out every source concurrently (mirroring the Node Promise.allSettled fan-out
// — one slow/failing source never blocks the others) and assembles the combined Result.
func runSources(ctx context.Context, target, kind string, sources map[string]sourceFunc) Result {
	result := Result{Target: target, Type: kind, Sources: make(map[string]SourceResult, len(sources)), FetchedAt: time.Now().UTC()}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(len(sources))
	for name, fn := range sources {
		name, fn := name, fn
		go func() {
			defer wg.Done()
			data, configured := fn(ctx)
			mu.Lock()
			result.Sources[name] = SourceResult{Configured: configured, Data: data}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return result
}

// LookupIP fans out to geo (3 independent sources, for forensic cross-corroboration) plus
// reverse_dns/rdap/virustotal/abuseipdb/shodan/greynoise, matching (and extending) the Node
// GET /api/osint/ip route's source set — the original "geo"/"reverse_dns"/"rdap" keys and
// their shapes are unchanged, so this stays backward compatible.
func LookupIP(ctx context.Context, client *httpx.Client, store *cache.Store, ip string, ttl time.Duration) Result {
	key := cacheKey("ip", ip)
	if cached, ok := getCached(store, key, ttl); ok {
		return cached
	}
	result := runSources(ctx, ip, "ip", map[string]sourceFunc{
		"geo":           func(ctx context.Context) (any, bool) { return lookupGeo(ctx, client, ip), true },
		"geo_freeipapi": func(ctx context.Context) (any, bool) { return lookupGeoFreeIPAPI(ctx, client, ip), true },
		"geo_ipwhois":   func(ctx context.Context) (any, bool) { return lookupGeoIPWhoIs(ctx, client, ip), true },
		"reverse_dns":   func(ctx context.Context) (any, bool) { return reverseDNS(ctx, ip), true },
		"rdap":          func(ctx context.Context) (any, bool) { return rdapLookup(ctx, client, "ip", ip), true },
		"greynoise":     func(ctx context.Context) (any, bool) { return lookupGreyNoise(ctx, client, ip), true },
		"virustotal": func(ctx context.Context) (any, bool) {
			return vtLookup(ctx, client, "ip_addresses", ip), vtConfigured()
		},
		"abuseipdb": func(ctx context.Context) (any, bool) { return abuseIPDBCheck(ctx, client, ip), abuseIPDBConfigured() },
		"shodan":    func(ctx context.Context) (any, bool) { return shodanLookup(ctx, client, ip), shodanConfigured() },
	})
	setCached(store, key, result)
	return result
}

// GeoConsensus summarizes agreement across the independent geolocation sources in an IP
// lookup Result — useful in a forensic report to state "N of M independent sources agree
// this IP is located in <country>" rather than trusting a single provider's answer.
type GeoConsensus struct {
	Country    string   `json:"country"`
	Agree      int      `json:"agree"`
	Total      int      `json:"total"`
	SourceList []string `json:"sources"`
}

// Consensus tallies the country returned by each geo_* source (plus the original "geo") and
// reports whichever country the most sources agree on. Returns ok=false if no geo source
// returned usable data (e.g. a private IP, or GEOIP_DISABLED).
func (r Result) GeoConsensusResult() (GeoConsensus, bool) {
	counts := map[string][]string{}
	for _, name := range []string{"geo", "geo_freeipapi", "geo_ipwhois"} {
		src, ok := r.Sources[name]
		if !ok || src.Data == nil {
			continue
		}
		m, ok := src.Data.(map[string]any)
		if !ok {
			continue
		}
		country, _ := m["country"].(string)
		if country == "" {
			continue
		}
		counts[country] = append(counts[country], name)
	}
	if len(counts) == 0 {
		return GeoConsensus{}, false
	}
	var best string
	var bestSources []string
	total := 0
	for country, sources := range counts {
		total += len(sources)
		if len(sources) > len(bestSources) {
			best, bestSources = country, sources
		}
	}
	return GeoConsensus{Country: best, Agree: len(bestSources), Total: total, SourceList: bestSources}, true
}

// LookupDomain fans out to rdap/crtsh/virustotal, matching GET /api/osint/domain.
func LookupDomain(ctx context.Context, client *httpx.Client, store *cache.Store, domain string, ttl time.Duration) Result {
	domain = strings.ToLower(domain)
	key := cacheKey("domain", domain)
	if cached, ok := getCached(store, key, ttl); ok {
		return cached
	}
	result := runSources(ctx, domain, "domain", map[string]sourceFunc{
		"rdap":       func(ctx context.Context) (any, bool) { return rdapLookup(ctx, client, "domain", domain), true },
		"crtsh":      func(ctx context.Context) (any, bool) { return crtSh(ctx, client, domain), true },
		"virustotal": func(ctx context.Context) (any, bool) { return vtLookup(ctx, client, "domains", domain), vtConfigured() },
	})
	setCached(store, key, result)
	return result
}

// LookupHash fans out to virustotal only, matching GET /api/osint/hash.
func LookupHash(ctx context.Context, client *httpx.Client, store *cache.Store, hash string, ttl time.Duration) Result {
	hash = strings.ToLower(hash)
	key := cacheKey("hash", hash)
	if cached, ok := getCached(store, key, ttl); ok {
		return cached
	}
	result := runSources(ctx, hash, "hash", map[string]sourceFunc{
		"virustotal": func(ctx context.Context) (any, bool) { return vtLookup(ctx, client, "files", hash), vtConfigured() },
	})
	setCached(store, key, result)
	return result
}

// LookupEmail reports domain-level RDAP/MX findings for the email's domain part — there is no
// free reputation source for a raw mailbox address, matching the Node route's own comment and
// behavior exactly (source names domain_rdap/domain_mx, not rdap/mx).
func LookupEmail(ctx context.Context, client *httpx.Client, store *cache.Store, email string, ttl time.Duration) Result {
	email = strings.ToLower(email)
	parts := strings.SplitN(email, "@", 2)
	domain := ""
	if len(parts) == 2 {
		domain = parts[1]
	}
	key := cacheKey("email-domain", domain)
	if cached, ok := getCached(store, key, ttl); ok {
		cached.Target = email
		cached.Type = "email"
		return cached
	}
	result := runSources(ctx, domain, "domain", map[string]sourceFunc{
		"domain_rdap": func(ctx context.Context) (any, bool) { return rdapLookup(ctx, client, "domain", domain), true },
		"domain_mx":   func(ctx context.Context) (any, bool) { return resolveMX(ctx, domain), true },
	})
	setCached(store, key, result)
	result.Target = email
	result.Type = "email"
	return result
}
