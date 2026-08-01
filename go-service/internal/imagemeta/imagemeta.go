// Package imagemeta extracts EXIF/IPTC/XMP metadata already embedded in evidence images —
// GPS coordinates, capture timestamp, camera make/model, software/editing history. This is
// read-only: nothing is inferred, matched against a database, or altered. Standard digital-
// forensics practice (the same data a tool like ExifTool would show), not intrusive analysis.
package imagemeta

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	im "github.com/bep/imagemeta"
)

var extFormats = map[string]im.ImageFormat{
	".jpg": im.JPEG, ".jpeg": im.JPEG,
	".tif": im.TIFF, ".tiff": im.TIFF,
	".png":  im.PNG,
	".webp": im.WebP,
	".heic": im.HEIF, ".heif": im.HEIF,
	".avif": im.AVIF,
	".dng":  im.DNG,
	".cr2":  im.CR2,
	".nef":  im.NEF,
	".arw":  im.ARW,
	".pef":  im.PEF,
}

// SupportedExt reports whether path has a file extension this package can extract metadata
// from — used by the analyzer to decide which files in an evidence set are images.
func SupportedExt(path string) bool {
	_, ok := extFormats[strings.ToLower(filepath.Ext(path))]
	return ok
}

func detectFormat(path string) (im.ImageFormat, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if f, ok := extFormats[ext]; ok {
		return f, nil
	}
	return 0, fmt.Errorf("unsupported image extension %q", ext)
}

// Result is everything extracted from one evidence image.
type Result struct {
	Path        string         `json:"path"`
	Format      string         `json:"format"`
	HasGPS      bool           `json:"has_gps"`
	Latitude    float64        `json:"latitude,omitempty"`
	Longitude   float64        `json:"longitude,omitempty"`
	MapURL      string         `json:"map_url,omitempty"`
	CapturedAt  *time.Time     `json:"captured_at,omitempty"`
	Make        string         `json:"make,omitempty"`
	Model       string         `json:"model,omitempty"`
	Software    string         `json:"software,omitempty"`
	Orientation string         `json:"orientation,omitempty"`
	EXIF        map[string]any `json:"exif,omitempty"`
	IPTC        map[string]any `json:"iptc,omitempty"`
	XMP         map[string]any `json:"xmp,omitempty"`
	Warning     string         `json:"warning,omitempty"`
}

// Extract reads EXIF/IPTC/XMP metadata from the image at path. Arbitrary evidence images are
// exactly the kind of untrusted input that can hit real parser edge cases (the underlying
// go-exif ecosystem has known GPS-IFD panics on some real-world camera output), so a panic
// during decode is recovered and reported as a Warning on a partial Result rather than
// aborting the whole batch.
func Extract(path string) (result Result, err error) {
	format, ferr := detectFormat(path)
	if ferr != nil {
		return Result{}, ferr
	}
	result.Path = path
	result.Format = format.String()

	defer func() {
		if r := recover(); r != nil {
			result.Warning = fmt.Sprintf("metadata extraction panicked: %v", r)
			err = nil
		}
	}()

	f, openErr := os.Open(path)
	if openErr != nil {
		return result, openErr
	}
	defer f.Close()

	var tags im.Tags
	_, decodeErr := im.Decode(im.Options{
		R:           f,
		ImageFormat: format,
		Sources:     im.EXIF | im.IPTC | im.XMP,
		HandleTag: func(info im.TagInfo) error {
			tags.Add(info)
			return nil
		},
	})
	if decodeErr != nil {
		result.Warning = decodeErr.Error()
		return result, nil
	}

	result.EXIF = flattenTags(tags.EXIF())
	result.IPTC = flattenTags(tags.IPTC())
	result.XMP = flattenTags(tags.XMP())

	// GetLatLong() returns (0, 0, nil) — no error — when there's simply no GPS tag at all
	// (confirmed in the library source), so a nil error alone doesn't mean GPS data was
	// found. Only trust it once we've confirmed a GPS tag actually exists in EXIF or XMP;
	// otherwise every non-geotagged photo (the common case: scans, screenshots, non-GPS
	// cameras) would incorrectly report HasGPS=true at exactly (0,0).
	_, exifHasGPS := result.EXIF["GPSLatitude"]
	_, xmpHasGPS := result.XMP["GPSLatitude"]
	if exifHasGPS || xmpHasGPS {
		if lat, lon, gpsErr := tags.GetLatLong(); gpsErr == nil {
			result.HasGPS = true
			result.Latitude = lat
			result.Longitude = lon
			result.MapURL = fmt.Sprintf("https://www.google.com/maps?q=%f,%f", lat, lon)
		}
	}
	if dt, dtErr := tags.GetDateTime(); dtErr == nil {
		result.CapturedAt = &dt
	}

	result.Make = strVal(result.EXIF["Make"])
	result.Model = strVal(result.EXIF["Model"])
	result.Software = strVal(result.EXIF["Software"])
	result.Orientation = strVal(result.EXIF["Orientation"])

	return result, nil
}

func flattenTags(m map[string]im.TagInfo) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v.Value
	}
	return out
}

func strVal(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
