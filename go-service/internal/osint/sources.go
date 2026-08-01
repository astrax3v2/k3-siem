// Package osint ports backend/src/routes/osint.js and its connector modules
// (virustotal.js, abuseipdb.js, shodan.js, geoip.js): on-demand enrichment for an
// IP/domain/hash/email, fanning out to several independent sources and caching the combined
// result to disk (via internal/cache) instead of the Node in-memory 24h Map — so a repeat
// lookup, or the offline analyzer, can serve it with zero network access once cached.
package osint

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"

	"k3siem/goservice/internal/httpx"
)

var privateIPRe = regexp.MustCompile(`^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)`)

func isPrivateIP(ip string) bool {
	return ip == "" || privateIPRe.MatchString(ip)
}

// lookupGeo ports geoip.js's lookupGeo(): free ip-api.com geolocation, skipped for private
// IPs or when GEOIP_DISABLED=true. Its own 24h in-memory cache in Node is superseded here by
// the outer disk cache wrapping the whole multi-source Result.
func lookupGeo(ctx context.Context, client *httpx.Client, ip string) any {
	if isPrivateIP(ip) || os.Getenv("GEOIP_DISABLED") == "true" {
		return nil
	}
	var data struct {
		Status      string  `json:"status"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
	}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,lat,lon,country,countryCode", url.QueryEscape(ip))
	if err := client.FetchJSON(ctx, url, httpx.FetchOptions{TimeoutMs: 3000}, &data); err != nil {
		return nil
	}
	if data.Status != "success" {
		return nil
	}
	return map[string]any{"lat": data.Lat, "lon": data.Lon, "country": data.Country, "countryCode": data.CountryCode}
}

// lookupGeoFreeIPAPI is a second, independent geolocation source (freeipapi.com — keyless,
// 60 req/min, explicit "commercial use allowed" ToS) for forensic cross-corroboration: two
// independent sources agreeing on a location is stronger evidence than one alone.
func lookupGeoFreeIPAPI(ctx context.Context, client *httpx.Client, ip string) any {
	if isPrivateIP(ip) || os.Getenv("GEOIP_DISABLED") == "true" {
		return nil
	}
	var data struct {
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		CountryName string  `json:"countryName"`
		CountryCode string  `json:"countryCode"`
		CityName    string  `json:"cityName"`
		RegionName  string  `json:"regionName"`
	}
	u := fmt.Sprintf("https://free.freeipapi.com/api/json/%s", url.QueryEscape(ip))
	if err := client.FetchJSON(ctx, u, httpx.FetchOptions{TimeoutMs: 5000}, &data); err != nil {
		return nil
	}
	if data.CountryCode == "" {
		return nil
	}
	return map[string]any{
		"lat": data.Latitude, "lon": data.Longitude, "country": data.CountryName,
		"countryCode": data.CountryCode, "city": data.CityName, "region": data.RegionName,
	}
}

// lookupGeoIPWhoIs is a third, independent geolocation source (ipwho.is — keyless, 1000
// req/day, explicit "commercial use allowed" ToS, richest field set of the free options
// including ISP/ASN) for the same cross-corroboration purpose.
func lookupGeoIPWhoIs(ctx context.Context, client *httpx.Client, ip string) any {
	if isPrivateIP(ip) || os.Getenv("GEOIP_DISABLED") == "true" {
		return nil
	}
	var data struct {
		Success    bool    `json:"success"`
		Country    string  `json:"country"`
		CountryCd  string  `json:"country_code"`
		City       string  `json:"city"`
		Region     string  `json:"region"`
		Latitude   float64 `json:"latitude"`
		Longitude  float64 `json:"longitude"`
		Connection struct {
			ISP string `json:"isp"`
			Org string `json:"org"`
			ASN int    `json:"asn"`
		} `json:"connection"`
	}
	u := fmt.Sprintf("https://ipwho.is/%s", url.QueryEscape(ip))
	if err := client.FetchJSON(ctx, u, httpx.FetchOptions{TimeoutMs: 5000}, &data); err != nil {
		return nil
	}
	if !data.Success {
		return nil
	}
	return map[string]any{
		"lat": data.Latitude, "lon": data.Longitude, "country": data.Country,
		"countryCode": data.CountryCd, "city": data.City, "region": data.Region,
		"isp": data.Connection.ISP, "org": data.Connection.Org, "asn": data.Connection.ASN,
	}
}

// lookupGreyNoise queries GreyNoise's Community API (keyless, anonymous — quota is tight,
// roughly 50 lookups/week combined across API+web, so this is meant for looking up specific
// IPs of interest during an investigation, not bulk scanning). It classifies an IP as
// internet-background "noise" (mass scanners/crawlers) vs. RIOT (known benign business
// service) vs. neither — useful for distinguishing opportunistic scan traffic from a
// targeted attack in a forensic report.
func lookupGreyNoise(ctx context.Context, client *httpx.Client, ip string) any {
	if isPrivateIP(ip) {
		return nil
	}
	var data any
	u := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", url.QueryEscape(ip))
	if err := client.FetchJSON(ctx, u, httpx.FetchOptions{TimeoutMs: 5000}, &data); err != nil {
		return nil
	}
	return data
}

// reverseDNS ports the Node `dns.promises.reverse(ip)` helper.
func reverseDNS(ctx context.Context, ip string) any {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil
	}
	return names
}

// rdapLookup ports the Node rdap(kind, target) helper — kind is "ip" or "domain".
func rdapLookup(ctx context.Context, client *httpx.Client, kind, target string) any {
	var data any
	u := fmt.Sprintf("https://rdap.org/%s/%s", kind, url.QueryEscape(target))
	if err := client.FetchJSON(ctx, u, httpx.FetchOptions{TimeoutMs: 8000}, &data); err != nil {
		return nil
	}
	return data
}

// crtSh ports the Node crtSh(domain) certificate-transparency lookup.
func crtSh(ctx context.Context, client *httpx.Client, domain string) any {
	var data any
	u := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	if err := client.FetchJSON(ctx, u, httpx.FetchOptions{TimeoutMs: 8000}, &data); err != nil {
		return nil
	}
	return data
}

// resolveMX ports the Node `dns.resolveMx(domain)` helper used for the /email route, mapping
// Go's net.MX shape onto Node's {exchange, priority} field names for downstream compatibility.
func resolveMX(ctx context.Context, domain string) any {
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(records) == 0 {
		return nil
	}
	out := make([]map[string]any, len(records))
	for i, r := range records {
		out[i] = map[string]any{"exchange": r.Host, "priority": r.Pref}
	}
	return out
}

func vtConfigured() bool { return os.Getenv("VIRUSTOTAL_API_KEY") != "" }

// vtLookup ports virustotal.js's lookupIp/lookupHash/lookupDomain — kind is the VT API path
// segment ("ip_addresses" | "files" | "domains").
func vtLookup(ctx context.Context, client *httpx.Client, kind, id string) any {
	if !vtConfigured() {
		return nil
	}
	var wrapper struct {
		Data struct {
			Attributes any `json:"attributes"`
		} `json:"data"`
	}
	u := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", kind, url.QueryEscape(id))
	err := client.FetchJSON(ctx, u, httpx.FetchOptions{
		Headers: map[string]string{"x-apikey": os.Getenv("VIRUSTOTAL_API_KEY")}, TimeoutMs: 8000,
	}, &wrapper)
	if err != nil {
		return nil
	}
	return wrapper.Data.Attributes
}

func abuseIPDBConfigured() bool { return os.Getenv("ABUSEIPDB_API_KEY") != "" }

// abuseIPDBCheck ports abuseipdb.js's checkIp().
func abuseIPDBCheck(ctx context.Context, client *httpx.Client, ip string) any {
	if !abuseIPDBConfigured() {
		return nil
	}
	var wrapper struct {
		Data any `json:"data"`
	}
	u := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", url.QueryEscape(ip))
	err := client.FetchJSON(ctx, u, httpx.FetchOptions{
		Headers: map[string]string{"Key": os.Getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"}, TimeoutMs: 8000,
	}, &wrapper)
	if err != nil {
		return nil
	}
	return wrapper.Data
}

func shodanConfigured() bool { return os.Getenv("SHODAN_API_KEY") != "" }

// shodanLookup ports shodan.js's lookupIp().
func shodanLookup(ctx context.Context, client *httpx.Client, ip string) any {
	if !shodanConfigured() {
		return nil
	}
	var data any
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", url.QueryEscape(ip), url.QueryEscape(os.Getenv("SHODAN_API_KEY")))
	if err := client.FetchJSON(ctx, u, httpx.FetchOptions{TimeoutMs: 8000}, &data); err != nil {
		return nil
	}
	return data
}
