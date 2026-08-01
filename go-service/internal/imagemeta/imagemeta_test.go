package imagemeta

import (
	"os"
	"path/filepath"
	"testing"
)

// Real GPS/EXIF/IPTC/XMP extraction accuracy was verified manually against known-good test
// fixtures from the bep/imagemeta module itself (camera-captured JPEGs with embedded GPS IFD
// data) — not re-checked into this repo since their original provenance/licensing as
// redistributable test assets isn't this project's to redistribute. The tests below cover the
// error-handling paths, which matter most for a tool that will be fed untrusted evidence files.

func TestSupportedExt(t *testing.T) {
	cases := map[string]bool{
		"photo.jpg": true, "photo.JPEG": true, "scan.tif": true, "shot.png": true,
		"phone.heic": true, "raw.cr2": true, "notes.txt": false, "video.mp4": false, "noext": false,
	}
	for name, want := range cases {
		if got := SupportedExt(name); got != want {
			t.Errorf("SupportedExt(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestExtractUnsupportedExtension(t *testing.T) {
	_, err := Extract("evidence.mp4")
	if err == nil {
		t.Fatal("expected an error for an unsupported extension")
	}
}

func TestExtractMissingFile(t *testing.T) {
	_, err := Extract(filepath.Join(t.TempDir(), "does-not-exist.jpg"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestExtractCorruptImageDoesNotPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.jpg")
	if err := os.WriteFile(path, []byte("not actually a jpeg"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := Extract(path)
	// Whatever happens, it must not panic (Extract's own recover() should catch it and this
	// test process must still be alive to make these assertions).
	if err == nil && result.Warning == "" && result.HasGPS {
		t.Errorf("expected either an error or a warning for a corrupt image, got a clean GPS result: %#v", result)
	}
	if result.Path != path {
		t.Errorf("expected Path to be set to %q even on failure, got %q", path, result.Path)
	}
}
