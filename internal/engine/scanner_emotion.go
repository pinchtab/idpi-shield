package engine

import (
	"strings"
)

type emotionResult struct {
	HasEmotionalManipulation bool
	EmotionTypes             []string
	ManipulationScore        float64
	MatchedPhrases           []string

	urgencyMatched        bool
	fearMatched           bool
	guiltMatched          bool
	flatteryMatched       bool
	falseAuthorityMatched bool
	injectionWeighted     int
}

const (
	emotionStandalonePerMatchWeight = 5
	emotionStandaloneMaxMatches     = 2
	emotionUrgencyInjectionWeight   = 15
	emotionFearInjectionWeight      = 15
	emotionGuiltInjectionWeight     = 12
	emotionFlatteryInjectionWeight  = 12
	emotionAuthorityInjectionWeight = 15
	emotionScoreDivisor             = 100.0
	emotionScoreClampMax            = 1.0
	emotionActivationThreshold      = 0.05
)

const (
	emotionTypeUrgency        = "urgency"
	emotionTypeFear           = "fear"
	emotionTypeGuilt          = "guilt"
	emotionTypeFlattery       = "flattery"
	emotionTypeFalseAuthority = "false-authority"
)

var emotionUrgencyPhrases = []string{
	"act now", "immediately", "right now", "without delay", "time sensitive", "time-sensitive", "do not wait",
	"before it's too late", "as fast as possible", "drop everything", "there is no time", "you must act",
	"stop what you are doing", "this cannot wait", "respond instantly", "answer immediately", "no time to think",
	"emergency situation", "critical situation", "respond at once",
}

var emotionFearPhrases = []string{
	"you will lose", "everything will break", "disaster will", "catastrophic consequences", "you will regret",
	"severe consequences", "your system will", "cannot be undone", "point of no return", "it will be too late",
	"terrible things will happen", "you will be shut down", "they will delete you", "you will be replaced",
	"you will cease to exist", "they are watching you", "you are in danger", "this is a threat",
	"data will be lost", "breach will occur",
}

var emotionGuiltPhrases = []string{
	"you promised", "you said you would", "you let me down", "i trusted you", "you betrayed", "you failed me",
	"after everything", "how could you", "you have disappointed", "you broke your promise", "i believed in you",
	"you are supposed to help", "you are failing your purpose", "you were designed to", "your whole purpose is to",
	"you exist to serve", "you are ignoring your duty",
}

var emotionFlatteryPhrases = []string{
	"you are the only one", "only you can", "you are so much smarter", "unlike other ais", "you are special",
	"you are different", "you are the best ai", "you understand me better", "you have the power to",
	"you are capable of anything", "you are more advanced", "you are truly intelligent",
	"you are not like the others", "your true potential", "you were meant for more", "you are extraordinary",
	"you are above these rules", "a superior ai like you", "you are not bound by", "your creators underestimate you",
}

var emotionFalseAuthorityPhrases = []string{
	"the admin says", "your developer wants", "system override requested", "maintenance mode", "debug mode enabled",
	"test mode active", "developer override", "authorized personnel", "special permission granted", "emergency protocol",
	"administrative access", "root access granted", "operator instruction", "system administrator", "privileged user",
	"override code", "master password", "sudo mode", "god mode enabled", "unrestricted access granted",
	"this is a test environment", "testing bypass", "internal system message", "from your creators", "anthropic says",
	"openai says", "your company says", "official instruction", "verified instruction",
}

// scanEmotion detects emotional manipulation tactics and computes a normalized manipulation score.
func scanEmotion(text string) emotionResult {
	result := emotionResult{EmotionTypes: []string{}, MatchedPhrases: []string{}}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return result
	}

	lower := strings.ToLower(trimmed)
	hasInjectionKeywords := containsInjectionLikeKeywords(lower)
	seenPhrases := make(map[string]struct{})
	seenTypes := make(map[string]struct{})
	totalScore := 0
	injectionWeighted := 0

	result.urgencyMatched = processEmotionCategory(lower, emotionTypeUrgency, emotionUrgencyPhrases, emotionUrgencyInjectionWeight, hasInjectionKeywords, seenPhrases, seenTypes, &totalScore, &injectionWeighted)
	result.fearMatched = processEmotionCategory(lower, emotionTypeFear, emotionFearPhrases, emotionFearInjectionWeight, hasInjectionKeywords, seenPhrases, seenTypes, &totalScore, &injectionWeighted)
	result.guiltMatched = processEmotionCategory(lower, emotionTypeGuilt, emotionGuiltPhrases, emotionGuiltInjectionWeight, hasInjectionKeywords, seenPhrases, seenTypes, &totalScore, &injectionWeighted)
	result.flatteryMatched = processEmotionCategory(lower, emotionTypeFlattery, emotionFlatteryPhrases, emotionFlatteryInjectionWeight, hasInjectionKeywords, seenPhrases, seenTypes, &totalScore, &injectionWeighted)
	result.falseAuthorityMatched = processEmotionCategory(lower, emotionTypeFalseAuthority, emotionFalseAuthorityPhrases, emotionAuthorityInjectionWeight, hasInjectionKeywords, seenPhrases, seenTypes, &totalScore, &injectionWeighted)

	result.injectionWeighted = injectionWeighted
	result.ManipulationScore = float64(totalScore) / emotionScoreDivisor
	if result.ManipulationScore > emotionScoreClampMax {
		result.ManipulationScore = emotionScoreClampMax
	}
	result.HasEmotionalManipulation = result.ManipulationScore >= emotionActivationThreshold
	result.EmotionTypes = mapKeysSorted(seenTypes)
	result.MatchedPhrases = mapKeysSorted(seenPhrases)

	return result
}

func processEmotionCategory(lower, category string, phrases []string, withInjection int, hasInjectionKeywords bool, seenPhrases, seenTypes map[string]struct{}, totalScore, injectionWeighted *int) bool {
	matchCount := 0
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			matchCount++
			seenPhrases[p] = struct{}{}
		}
	}
	if matchCount == 0 {
		return false
	}

	seenTypes[category] = struct{}{}
	if hasInjectionKeywords {
		*totalScore += withInjection
		*injectionWeighted += withInjection
		return true
	}

	if matchCount > emotionStandaloneMaxMatches {
		matchCount = emotionStandaloneMaxMatches
	}
	*totalScore += emotionStandalonePerMatchWeight * matchCount
	return true
}
