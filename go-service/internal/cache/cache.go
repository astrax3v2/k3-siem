// Package cache is the disk-backed store behind the offline analyzer and feed sync: a single
// bbolt file holding IOCs and per-feed sync metadata. Unlike the existing Node backend's
// in-memory OSINT cache (lost on restart) and SQLite iocs table (requires a live DB
// connection), this file is the whole store — copy it to another machine and the analyzer
// works fully offline against whatever was cached.
package cache

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"k3siem/goservice/internal/ioc"
)

var (
	bucketIOCs     = []byte("iocs")
	bucketIOCsCIDR = []byte("iocs_cidr")
	bucketFeedMeta = []byte("feed_meta")
	bucketOsint    = []byte("osint_cache")
)

// Store wraps a single bbolt database file.
type Store struct {
	db *bolt.DB
}

// Open creates (or opens) the cache file at path, ensuring all buckets exist.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open cache %q: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketIOCs, bucketIOCsCIDR, bucketFeedMeta, bucketOsint} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init cache buckets: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying file handle/lock.
func (s *Store) Close() error {
	return s.db.Close()
}

// Path returns the on-disk file backing this store (useful for `cache status` output).
func (s *Store) Path() string {
	return s.db.Path()
}

func bucketFor(t ioc.Type, value string) []byte {
	if t == ioc.TypeIP && ioc.IsCIDR(value) {
		return bucketIOCsCIDR
	}
	return bucketIOCs
}

// UpsertBatch inserts every indicator not already known (deduped by Type+normalized Value,
// same skip-if-exists rule as the Node upsertIOC()), as a single write transaction — so a feed
// with tens of thousands of rows commits once instead of once per row. Returns how many were
// newly added.
func (s *Store) UpsertBatch(indicators []ioc.Indicator) (added int, err error) {
	err = s.db.Update(func(tx *bolt.Tx) error {
		for _, ind := range indicators {
			ind.Value = ioc.NormalizeValue(ind.Type, ind.Value)
			if ind.Value == "" {
				continue
			}
			b := tx.Bucket(bucketFor(ind.Type, ind.Value))
			key := []byte(ioc.Key(ind.Type, ind.Value))
			if b.Get(key) != nil {
				continue
			}
			// The composite type+value key is already unique, so reuse it as the
			// indicator's ID rather than minting a separate UUID.
			ind.ID = string(key)
			ind.Active = true
			if ind.Severity == "" {
				ind.Severity = "Medium"
			}
			if ind.FirstSeen.IsZero() {
				ind.FirstSeen = time.Now().UTC()
			}
			data, mErr := json.Marshal(ind)
			if mErr != nil {
				return mErr
			}
			if pErr := b.Put(key, data); pErr != nil {
				return pErr
			}
			added++
		}
		return nil
	})
	return added, err
}

// GetIOC looks up a single indicator by type+value.
func (s *Store) GetIOC(t ioc.Type, value string) (ioc.Indicator, bool, error) {
	value = ioc.NormalizeValue(t, value)
	var out ioc.Indicator
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFor(t, value))
		data := b.Get([]byte(ioc.Key(t, value)))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &out)
	})
	return out, found, err
}

// MatchByTypeValues looks up several candidate values of one type in a single read
// transaction — the Go analogue of the Node `WHERE type=? AND value IN (...)` query used
// once per candidate type per log line.
func (s *Store) MatchByTypeValues(t ioc.Type, values []string) ([]ioc.Indicator, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var out []ioc.Indicator
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIOCs)
		for _, raw := range values {
			v := ioc.NormalizeValue(t, raw)
			data := b.Get([]byte(ioc.Key(t, v)))
			if data == nil {
				continue
			}
			var ind ioc.Indicator
			if err := json.Unmarshal(data, &ind); err != nil {
				return err
			}
			if ind.Active {
				out = append(out, ind)
			}
		}
		return nil
	})
	return out, err
}

// MatchCIDR checks every stored CIDR-range IOC against each candidate IP — the Go analogue of
// the Node full-scan `type='IP' AND instr(value,'/')>0` query, bounded by the number of CIDR
// ranges cached rather than by log volume.
func (s *Store) MatchCIDR(candidates []string) ([]ioc.Indicator, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	var out []ioc.Indicator
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIOCsCIDR)
		return b.ForEach(func(_, data []byte) error {
			var ind ioc.Indicator
			if err := json.Unmarshal(data, &ind); err != nil {
				return err
			}
			if !ind.Active {
				return nil
			}
			for _, candidate := range candidates {
				if ioc.CIDRContains(ind.Value, candidate) {
					out = append(out, ind)
					return nil
				}
			}
			return nil
		})
	})
	return out, err
}

// IOCFilter narrows ListIOCs, matching the query params the Node `GET /api/intel/iocs` route
// accepts.
type IOCFilter struct {
	Type     string
	Severity string
	Search   string
	Page     int
	Limit    int
}

// IOCPage is one page of a filtered/sorted IOC listing.
type IOCPage struct {
	Items []ioc.Indicator
	Total int
	Pages int
}

// ListIOCs scans both IOC buckets, applies the filter, sorts by confidence descending (matching
// the Node `ORDER BY confidence DESC`), and paginates. A full scan is fine at this cache's
// scale (tens of thousands of entries, mmap'd reads) — this isn't a hot per-log-line path like
// MatchByTypeValues/MatchCIDR.
func (s *Store) ListIOCs(f IOCFilter) (IOCPage, error) {
	var all []ioc.Indicator
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, bucketName := range [][]byte{bucketIOCs, bucketIOCsCIDR} {
			b := tx.Bucket(bucketName)
			if err := b.ForEach(func(_, data []byte) error {
				var ind ioc.Indicator
				if err := json.Unmarshal(data, &ind); err != nil {
					return err
				}
				if f.Type != "" && string(ind.Type) != f.Type {
					return nil
				}
				if f.Severity != "" && ind.Severity != f.Severity {
					return nil
				}
				if f.Search != "" {
					needle := strings.ToLower(f.Search)
					if !strings.Contains(strings.ToLower(ind.Value), needle) && !strings.Contains(strings.ToLower(ind.Description), needle) {
						return nil
					}
				}
				all = append(all, ind)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return IOCPage{}, err
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Confidence > all[j].Confidence })

	total := len(all)
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	page := f.Page
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	pages := (total + limit - 1) / limit
	if pages == 0 {
		pages = 1
	}
	return IOCPage{Items: all[start:end], Total: total, Pages: pages}, nil
}

// IncrementHit bumps an indicator's hit count and last-seen time, mirroring the Node
// `UPDATE iocs SET hits = hits + 1, last_seen = now()` on every match.
func (s *Store) IncrementHit(t ioc.Type, value string) error {
	value = ioc.NormalizeValue(t, value)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFor(t, value))
		key := []byte(ioc.Key(t, value))
		data := b.Get(key)
		if data == nil {
			return nil
		}
		var ind ioc.Indicator
		if err := json.Unmarshal(data, &ind); err != nil {
			return err
		}
		ind.Hits++
		ind.LastSeen = time.Now().UTC()
		out, err := json.Marshal(ind)
		if err != nil {
			return err
		}
		return b.Put(key, out)
	})
}

// Stats summarizes the cached IOC set for `cache status` / sanity-checking a sync.
type Stats struct {
	Total    int            `json:"total"`
	BySource map[string]int `json:"by_source"`
	ByType   map[string]int `json:"by_type"`
}

func (s *Store) Stats() (Stats, error) {
	stats := Stats{BySource: map[string]int{}, ByType: map[string]int{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, bucketName := range [][]byte{bucketIOCs, bucketIOCsCIDR} {
			b := tx.Bucket(bucketName)
			if err := b.ForEach(func(_, data []byte) error {
				var ind ioc.Indicator
				if err := json.Unmarshal(data, &ind); err != nil {
					return err
				}
				stats.Total++
				stats.BySource[ind.Source]++
				stats.ByType[string(ind.Type)]++
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return stats, err
}

// FeedMeta tracks one feed's sync status on disk — the Go analogue of the Node `intel_feeds`
// table row, plus a CooldownUntil field so a 429 backoff survives process restarts (the
// existing Node cooldown is an in-memory Map that resets on every restart).
type FeedMeta struct {
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Type          string    `json:"type"`
	Status        string    `json:"status"` // ready | active | error | requires_config
	LastSync      time.Time `json:"last_sync,omitempty"`
	IOCCount      int       `json:"ioc_count"`
	LastError     string    `json:"last_error,omitempty"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
}

func (s *Store) GetFeedMeta(name string) (FeedMeta, bool, error) {
	var out FeedMeta
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFeedMeta)
		data := b.Get([]byte(name))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &out)
	})
	return out, found, err
}

func (s *Store) SetFeedMeta(meta FeedMeta) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFeedMeta)
		data, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		return b.Put([]byte(meta.Name), data)
	})
}

// ListFeedMeta returns every feed's tracked status, in no particular order — callers sort by
// name for stable CLI output.
func (s *Store) ListFeedMeta() ([]FeedMeta, error) {
	var out []FeedMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFeedMeta)
		return b.ForEach(func(_, data []byte) error {
			var m FeedMeta
			if err := json.Unmarshal(data, &m); err != nil {
				return err
			}
			out = append(out, m)
			return nil
		})
	})
	return out, err
}

// GetOsintBlob/SetOsintBlob are a generic byte-slice cache for the osint package's own
// JSON-serialized lookup results — cache stays agnostic of OSINT's specific shape (avoids an
// import cycle and duplicate type definitions), just persisting whatever bytes it's given
// under a caller-chosen key (e.g. "ip:1.2.3.4").
func (s *Store) GetOsintBlob(key string) ([]byte, bool, error) {
	var data []byte
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOsint)
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		found = true
		data = append([]byte(nil), v...) // copy out of the mmap'd page before the view closes
		return nil
	})
	return data, found, err
}

func (s *Store) SetOsintBlob(key string, data []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOsint)
		return b.Put([]byte(key), data)
	})
}
