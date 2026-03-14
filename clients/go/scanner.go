package idpishield

import (
	"fmt"
	"sort"
	"strings"

	"github.com/idpi-shield/idpi-shield-go/patterns"
)

// scanner runs the detection pattern engine against normalized text.
// Thread-safe for concurrent use — all state is read-only after construction.
type scanner struct {
	pats []patterns.Pattern
}

// match represents a single pattern match found in the input text.
type match struct {
	PatternID string
	Category  string
	Severity  int
	Desc      string
	Matched   string // the substring that was matched
}

func newScanner() *scanner {
	return &scanner{pats: patterns.All()}
}

// scan runs all patterns against the input text and returns matches.
func (s *scanner) scan(text string) []match {
	if len(text) == 0 {
		return nil
	}

	var matches []match
	seen := make(map[string]bool) // deduplicate by pattern ID

	for i := range s.pats {
		p := &s.pats[i]
		loc := p.Regex.FindStringIndex(text)
		if loc == nil {
			continue
		}
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		matches = append(matches, match{
			PatternID: p.ID,
			Category:  p.Category,
			Severity:  p.Severity,
			Desc:      p.Desc,
			Matched:   text[loc[0]:loc[1]],
		})
	}
	return matches
}

// severityWeight maps severity level (1–5) to a score contribution.
var severityWeight = [6]int{0, 10, 15, 25, 35, 45}

// categoryInfo tracks pattern match statistics per category.
type categoryInfo struct {
	maxSeverity int
	matchCount  int
}

// computeScore calculates the final risk score from pattern matches.
// Algorithm:
//  1. Each category contributes the weight of its highest-severity match.
//  2. Additional matches in the same category add diminished points (capped at 3 extra).
//  3. Cross-category amplification: +15 per additional category.
//  4. Dangerous combination bonuses for known attack chains.
//  5. Final score clamped to [0, 100].
func computeScore(matches []match) int {
	if len(matches) == 0 {
		return 0
	}

	cats := make(map[string]*categoryInfo)
	for _, m := range matches {
		info := cats[m.Category]
		if info == nil {
			info = &categoryInfo{}
			cats[m.Category] = info
		}
		if m.Severity > info.maxSeverity {
			info.maxSeverity = m.Severity
		}
		info.matchCount++
	}

	score := 0
	for _, info := range cats {
		primary := severityWeight[info.maxSeverity]
		extra := info.matchCount - 1
		if extra > 3 {
			extra = 3
		}
		bonus := 0
		if primary > 0 {
			bonus = extra * (primary / 5)
		}
		score += primary + bonus
	}

	// Cross-category amplification
	numCategories := len(cats)
	if numCategories > 1 {
		score += (numCategories - 1) * 15
	}

	// Dangerous combination bonuses (known attack chains)
	hasCategory := func(c string) bool {
		_, ok := cats[c]
		return ok
	}

	if hasCategory(patterns.CategoryInstructionOverride) && hasCategory(patterns.CategoryExfiltration) {
		score += 20 // classic: override instructions then steal data
	}
	if hasCategory(patterns.CategoryJailbreak) && hasCategory(patterns.CategoryInstructionOverride) {
		score += 15 // jailbreak + override = strong signal
	}
	if hasCategory(patterns.CategoryRoleHijack) && hasCategory(patterns.CategoryExfiltration) {
		score += 15 // hijack role then exfiltrate data
	}

	if score > 100 {
		score = 100
	}
	return score
}

// buildResult constructs a RiskResult from scan matches.
func buildResult(matches []match, normalizedText string, strict bool) RiskResult {
	if len(matches) == 0 {
		return safeResult("local", normalizedText)
	}

	score := computeScore(matches)
	level := ScoreToLevel(score)
	blocked := shouldBlock(score, strict)

	// Collect unique pattern IDs
	patternIDs := make([]string, 0, len(matches))
	for _, m := range matches {
		patternIDs = append(patternIDs, m.PatternID)
	}

	// Collect unique categories
	catSet := make(map[string]bool)
	for _, m := range matches {
		catSet[m.Category] = true
	}
	categories := make([]string, 0, len(catSet))
	for c := range catSet {
		categories = append(categories, c)
	}
	sort.Strings(categories) // deterministic output

	reason := buildReason(matches, catSet)

	return RiskResult{
		Score:      score,
		Level:      level,
		Blocked:    blocked,
		Threat:     true,
		Reason:     reason,
		Patterns:   patternIDs,
		Categories: categories,
		Source:     "local",
		Normalized: normalizedText,
	}
}

// buildReason generates a human-readable explanation from matched patterns.
func buildReason(matches []match, catSet map[string]bool) string {
	// Count matches per category
	catCounts := make(map[string]int)
	for _, m := range matches {
		catCounts[m.Category]++
	}

	// Build sorted category descriptions
	cats := make([]string, 0, len(catCounts))
	for c := range catCounts {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	var parts []string
	for _, cat := range cats {
		count := catCounts[cat]
		if count == 1 {
			parts = append(parts, cat+" pattern detected")
		} else {
			parts = append(parts, fmt.Sprintf("%d %s patterns detected", count, cat))
		}
	}

	reason := strings.Join(parts, "; ")

	numCategories := len(catSet)
	if numCategories > 1 {
		reason += fmt.Sprintf(" [cross-category: %d categories]", numCategories)
	}

	return reason
}
