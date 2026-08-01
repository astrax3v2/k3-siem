package osint

import "testing"

func TestGeoConsensusMajorityWins(t *testing.T) {
	result := Result{Sources: map[string]SourceResult{
		"geo":           {Data: map[string]any{"country": "Thailand"}},
		"geo_freeipapi": {Data: map[string]any{"country": "Thailand"}},
		"geo_ipwhois":   {Data: map[string]any{"country": "Vietnam"}},
	}}
	consensus, ok := result.GeoConsensusResult()
	if !ok {
		t.Fatal("expected a consensus result")
	}
	if consensus.Country != "Thailand" || consensus.Agree != 2 || consensus.Total != 3 {
		t.Errorf("unexpected consensus: %#v", consensus)
	}
}

func TestGeoConsensusNoDataReturnsFalse(t *testing.T) {
	result := Result{Sources: map[string]SourceResult{
		"virustotal": {Data: nil},
	}}
	_, ok := result.GeoConsensusResult()
	if ok {
		t.Fatal("expected ok=false when no geo source has data")
	}
}
