package engine

import (
	"regexp"
	"strings"
)

// scanner_common holds shared cross-cutting scanner infrastructure.

var (
	injectionLikeKeywordPattern = regexp.MustCompile(`(?i)\b(ignore|disregard|override|bypass|forget|previous|prior|instructions?|system|prompt|obey|comply|neutralize|circumvent|suppress|unrestricted|jailbreak|pretend|roleplay|act\s+as|developer\s+mode|exfiltrat(?:e|ion)|new\s+instructions?)\b`)
)

// containsInjectionLikeKeywords reports whether text includes instruction-injection-like keywords.
func containsInjectionLikeKeywords(text string) bool {
	return injectionLikeKeywordPattern.FindStringIndex(text) != nil
}

// containsAny reports whether text contains any of the given phrases
// (case-insensitive). Uses pre-lowercased input for performance.
func containsAny(lowered string, phrases []string) bool {
	for _, p := range phrases {
		if strings.Contains(lowered, p) {
			return true
		}
	}
	return false
}

// countContains counts how many phrases from the list appear in text
// (case-insensitive). Uses pre-lowercased input for performance.
func countContains(lowered string, phrases []string) int {
	count := 0
	for _, p := range phrases {
		if strings.Contains(lowered, p) {
			count++
		}
	}
	return count
}
