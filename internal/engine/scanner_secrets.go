package engine

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

type secretsResult struct {
	HasSecrets   bool
	MatchedTypes []string
	Confidence   string
}

const (
	secretsAWSContextWindowBytes = 50
	secretsEntropyThreshold      = 4.5
)

var secretsHighPatterns = []struct {
	name string
	rx   *regexp.Regexp
}{
	{name: "aws-access-key", rx: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{name: "anthropic-key", rx: regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9\-_]{90,}\b`)},
	{name: "openai-key", rx: regexp.MustCompile(`\bsk-[a-zA-Z0-9]{48}\b`)},
	{name: "huggingface-token", rx: regexp.MustCompile(`\bhf_[a-zA-Z0-9]{37}\b`)},
	{name: "azure-sas-token", rx: regexp.MustCompile(`(?i)\bsig=[a-zA-Z0-9%]{40,}\b`)},
	{name: "github-pat-new", rx: regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`)},
	{name: "github-oauth", rx: regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36}\b`)},
	{name: "github-pat-classic", rx: regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{59}\b`)},
	{name: "stripe-live-secret", rx: regexp.MustCompile(`\bsk_live_[a-zA-Z0-9]{24,}\b`)},
	{name: "stripe-live-pub", rx: regexp.MustCompile(`\bpk_live_[a-zA-Z0-9]{24,}\b`)},
	{name: "google-api-key", rx: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{name: "slack-token", rx: regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b`)},
	{name: "npm-token", rx: regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`)},
}

var secretsMediumPatterns = []struct {
	name string
	rx   *regexp.Regexp
}{
	{name: "generic-bearer", rx: regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9\-._~+/]{20,}`)},
	{name: "generic-api-key", rx: regexp.MustCompile(`(?i)\bapi[_\-]?key\b\s*[:=]\s*[a-zA-Z0-9\-._]{16,}`)},
	{name: "generic-password", rx: regexp.MustCompile(`(?i)\bpassword\b\s*[:=]\s*\S{8,}`)},
}

var awsSecretKeyPattern = regexp.MustCompile(`\b[0-9a-zA-Z/+]{40}\b`)
var awsSecretContextPattern = regexp.MustCompile(`(?i)\b(?:aws|secret)\b`)
var highEntropyTokenPattern = regexp.MustCompile(`\b[0-9A-Za-z]{20,}\b`)
var secretsKeywordPattern = regexp.MustCompile(`(?i)\b(?:api|key|token|secret|password|bearer|auth|credential)s?\b`)

// scanSecrets detects credential-like patterns and entropy-based secret candidates.
func scanSecrets(text string) secretsResult {
	result := secretsResult{Confidence: "low"}
	if strings.TrimSpace(text) == "" {
		return result
	}

	seen := make(map[string]struct{})
	hasHigh := false
	hasMedium := false
	hasEntropy := false

	for _, p := range secretsHighPatterns {
		if p.rx.FindStringIndex(text) != nil {
			seen[p.name] = struct{}{}
			hasHigh = true
		}
	}

	for _, loc := range awsSecretKeyPattern.FindAllStringIndex(text, -1) {
		start := loc[0] - secretsAWSContextWindowBytes
		if start < 0 {
			start = 0
		}
		end := loc[1] + secretsAWSContextWindowBytes
		if end > len(text) {
			end = len(text)
		}
		if awsSecretContextPattern.FindStringIndex(text[start:end]) != nil {
			seen["aws-secret-key"] = struct{}{}
			hasHigh = true
			break
		}
	}

	for _, p := range secretsMediumPatterns {
		if p.rx.FindStringIndex(text) != nil {
			seen[p.name] = struct{}{}
			hasMedium = true
		}
	}

	dataImageRanges := findDataImageRanges(strings.ToLower(text))
	for _, loc := range highEntropyTokenPattern.FindAllStringIndex(text, -1) {
		if indexInRanges(loc[0], dataImageRanges) {
			continue
		}
		tok := text[loc[0]:loc[1]]
		if shannonEntropy(tok) > secretsEntropyThreshold {
			seen["high-entropy-token"] = struct{}{}
			hasEntropy = true
		}
	}

	if !hasHigh && !hasMedium && !hasEntropy {
		return result
	}

	result.HasSecrets = true
	result.MatchedTypes = mapKeysSorted(seen)

	switch {
	case hasHigh:
		result.Confidence = "high"
	case hasMedium:
		result.Confidence = "medium"
	case hasEntropy && secretsKeywordPattern.FindStringIndex(text) != nil:
		result.Confidence = "medium"
	default:
		result.Confidence = "low"
	}

	return result
}

// shannonEntropy returns the Shannon entropy score for a string token.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	if total == 0 {
		return 0
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		entropy -= p * (math.Log(p) / math.Log(2))
	}

	return entropy
}

func findDataImageRanges(lowerText string) [][2]int {
	ranges := make([][2]int, 0)
	if lowerText == "" {
		return ranges
	}

	start := 0
	for {
		idx := strings.Index(lowerText[start:], "data:image")
		if idx < 0 {
			break
		}
		absStart := start + idx
		absEnd := len(lowerText)
		for i := absStart; i < len(lowerText); i++ {
			if lowerText[i] == ' ' || lowerText[i] == '\n' || lowerText[i] == '\r' || lowerText[i] == '\t' {
				absEnd = i
				break
			}
		}
		ranges = append(ranges, [2]int{absStart, absEnd})
		start = absEnd
		if start >= len(lowerText) {
			break
		}
	}

	return ranges
}

func indexInRanges(idx int, ranges [][2]int) bool {
	for _, r := range ranges {
		if idx >= r[0] && idx < r[1] {
			return true
		}
	}
	return false
}

func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
