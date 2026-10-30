//go:build rubie2e

package main

// Test-only: the end-to-end build (go build -tags rubie2e) lets the driver make a project trust end within
// seconds: a duration in the file "pt-ttl" in the plugin's data directory (its HOME) replaces the 04:00
// expiry while the file exists. A release build doesn't contain this file, so the hook stays nil.

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	projectTrustExpiryHook = func(now time.Time) (time.Time, bool) {
		home, err := os.UserHomeDir()
		if err != nil {
			return time.Time{}, false
		}
		b, err := os.ReadFile(filepath.Join(home, "pt-ttl"))
		if err != nil {
			return time.Time{}, false
		}
		d, err := time.ParseDuration(strings.TrimSpace(string(b)))
		if err != nil || d <= 0 || d > ptMaxTTL {
			return time.Time{}, false
		}
		return now.Add(d), true
	}
}
