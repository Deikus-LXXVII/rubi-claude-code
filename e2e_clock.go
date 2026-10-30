//go:build rubie2e

package main

// Test-only: the end-to-end build lets the driver move the plugin's clock forward: a duration in the file
// "clock-offset" in the plugin's data directory (its HOME) is added to the time while the file exists, so the
// driver can check that a trust until revoked is still valid after days. A release build doesn't contain this
// file, so the hook stays nil.

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	clockHook = func(now time.Time) time.Time {
		home, err := os.UserHomeDir()
		if err != nil {
			return now
		}
		b, err := os.ReadFile(filepath.Join(home, "clock-offset"))
		if err != nil {
			return now
		}
		d, err := time.ParseDuration(strings.TrimSpace(string(b)))
		if err != nil || d < 0 || d > 3650*24*time.Hour {
			return now
		}
		return now.Add(d)
	}
}
