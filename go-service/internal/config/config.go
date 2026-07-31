// Package config provides minimal .env file loading — no external dependency needed for
// simple KEY=VALUE lines, which is all the OSINT/feed API keys need.
package config

import (
	"bufio"
	"os"
	"strings"
)

// LoadDotEnv reads simple KEY=VALUE lines from path into the process environment. Keys already
// set in the real environment are left untouched (the file only fills gaps), and a missing
// file is silently skipped — callers can try several candidate paths in order.
func LoadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}
