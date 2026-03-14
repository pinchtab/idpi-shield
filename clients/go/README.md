# idpi-shield Go Client

**Zero-dependency defense against Indirect Prompt Injection for Go applications.**

[![Go Reference](https://pkg.go.dev/badge/github.com/idpi-shield/idpi-shield-go.svg)](https://pkg.go.dev/github.com/idpi-shield/idpi-shield-go)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

## Install

```bash
go get github.com/idpi-shield/idpi-shield-go
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	shield "github.com/idpi-shield/idpi-shield-go"
)

func main() {
	client := shield.New(shield.Config{
		Mode:           shield.ModeBalanced,
		AllowedDomains: []string{"example.com", "*.trusted.org"},
	})

	// Check domain before navigating
	result := client.CheckDomain("https://suspicious-site.com/page")
	if result.Blocked {
		log.Fatalf("Domain blocked: %s", result.Reason)
	}

	// Scan page content before passing to AI
	pageText := "... web page content ..."
	result = client.Scan(pageText)
	fmt.Printf("Risk: %d/100 (%s)\n", result.Score, result.Level)
	if result.Blocked {
		log.Fatalf("Content blocked: %s", result.Reason)
	}

	// Wrap content with trust boundaries before sending to LLM
	safe := client.Wrap(pageText, "https://example.com/article")
	// Pass 'safe' to your LLM instead of raw pageText
	_ = safe
}
```

## Configuration

```go
cfg := shield.Config{
	// Analysis depth: ModeLight | ModeBalanced (default) | ModeSmart
	Mode: shield.ModeBalanced,

	// Domain allowlist (empty = allow all)
	AllowedDomains: []string{"example.com", "*.trusted.org"},

	// Lower blocking thresholds (score >= 40 blocks instead of >= 60)
	StrictMode: false,

	// Tier 2 service URL (only used with ModeSmart)
	ServiceURL: "http://localhost:7432",

	// Service request timeout (default: 5s)
	ServiceTimeout: 3 * time.Second,
}
```

## Modes

| Mode | Speed | What It Does |
|------|-------|-------------|
| `ModeLight` | < 0.1ms | Pattern matching only, no normalization |
| `ModeBalanced` | < 1ms | Pattern matching + Unicode normalization + domain checking |
| `ModeSmart` | 1-5ms locally, 50-200ms with service | Balanced + service escalation for high-risk content |

## API

### `New(cfg Config) *Client`
Creates a new idpi-shield client. Safe for concurrent use.

### `Scan(text string) RiskResult`
Analyzes text for prompt injection threats. Returns a `RiskResult` with score (0-100), severity level, and matched patterns.

### `ScanContext(ctx context.Context, text string) RiskResult`
Like `Scan` but accepts a context for controlling service call cancellation (smart mode).

### `CheckDomain(rawURL string) RiskResult`
Checks if a URL's domain is in the configured allowlist.

### `Wrap(content, sourceURL string) string`
Wraps untrusted content with XML-style trust boundary markers for LLM consumption.

## RiskResult

```go
type RiskResult struct {
	Score      int      // 0-100 risk score
	Level      Level    // "safe" | "low" | "medium" | "high" | "critical"
	Blocked    bool     // true if content was blocked
	Threat     bool     // true if any threat signal detected
	Reason     string   // human-readable explanation
	Patterns   []string // IDs of matched patterns
	Categories []string // unique threat categories detected
	Source     string   // "local" or "service"
	Normalized string   // normalized text used for analysis
}
```

## Threat Categories

| Category | Description |
|----------|-------------|
| `instruction-override` | Attempts to override the AI's original instructions |
| `exfiltration` | Attempts to extract or transmit sensitive data |
| `role-hijack` | Attempts to change the AI's identity or persona |
| `jailbreak` | Attempts to remove safety restrictions |
| `indirect-command` | Attempts to inject new tasks or commands |
| `social-engineering` | Attempts to impersonate system authority |
| `structural-injection` | Attacks via HTML comments or fake system tags |

## Detection Coverage

- **88 patterns** across 7 threat categories
- **5 languages**: English, French, Spanish, German, Japanese
- **Unicode defense**: Defeats zero-width character insertion, Cyrillic/Greek homoglyph substitution, full-width character obfuscation
- **Attack chain detection**: Amplified scoring for multi-category attacks

## Thread Safety

`Client` is safe for concurrent use by multiple goroutines. Create once, use everywhere.

## Zero Dependencies

This library uses only Go's standard library. No external packages required.
