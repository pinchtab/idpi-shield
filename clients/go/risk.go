package idpishield

import "strings"

// Mode configures the analysis depth of the scanner.
type Mode int

const (
	// ModeLight performs pattern matching only against raw input.
	// No Unicode normalization. Fastest mode (< 0.1ms).
	ModeLight Mode = iota

	// ModeBalanced applies Unicode normalization before pattern matching
	// and checks domain allowlists. Default mode (< 1ms).
	ModeBalanced

	// ModeSmart includes all balanced analysis plus optional escalation
	// to the idpi-shield service for deep semantic analysis.
	ModeSmart
)

// String returns the string representation of Mode.
func (m Mode) String() string {
	switch m {
	case ModeLight:
		return "light"
	case ModeBalanced:
		return "balanced"
	case ModeSmart:
		return "smart"
	default:
		return "balanced"
	}
}

// ParseMode converts a string to a Mode value.
// Returns ModeBalanced for unrecognized values.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "light":
		return ModeLight
	case "balanced":
		return ModeBalanced
	case "smart":
		return ModeSmart
	default:
		return ModeBalanced
	}
}

// Level represents the severity classification of a risk assessment.
type Level string

const (
	LevelSafe     Level = "safe"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

// RiskResult is the canonical return type for all idpi-shield analysis operations.
// Every client library and the service returns this exact structure.
type RiskResult struct {
	// Score is the risk score from 0 (clean) to 100 (confirmed attack).
	Score int `json:"score"`

	// Level is the severity label derived from Score.
	Level Level `json:"level"`

	// Blocked indicates whether the content was blocked based on the current configuration.
	Blocked bool `json:"blocked"`

	// Threat indicates whether any threat signal was detected, regardless of blocking decision.
	Threat bool `json:"threat"`

	// Reason is a human-readable explanation of the analysis result.
	Reason string `json:"reason"`

	// Patterns lists the IDs of patterns that matched.
	Patterns []string `json:"patterns"`

	// Categories lists the unique threat categories detected.
	Categories []string `json:"categories"`

	// Source indicates where analysis was performed: "local" or "service".
	Source string `json:"source"`

	// Normalized is the unicode-normalized text used for analysis (for audit).
	// Empty when normalization was not applied (e.g., light mode).
	Normalized string `json:"normalized"`
}

// ScoreToLevel maps a 0–100 score to its corresponding severity level.
func ScoreToLevel(score int) Level {
	switch {
	case score < 20:
		return LevelSafe
	case score < 40:
		return LevelLow
	case score < 60:
		return LevelMedium
	case score < 80:
		return LevelHigh
	default:
		return LevelCritical
	}
}

// shouldBlock determines whether content should be blocked given a score and config.
func shouldBlock(score int, strict bool) bool {
	if strict {
		return score >= 40
	}
	return score >= 60
}

// safeResult returns a clean RiskResult with no threats detected.
func safeResult(source, normalized string) RiskResult {
	return RiskResult{
		Score:      0,
		Level:      LevelSafe,
		Blocked:    false,
		Threat:     false,
		Reason:     "No threats detected",
		Patterns:   []string{},
		Categories: []string{},
		Source:      source,
		Normalized: normalized,
	}
}
