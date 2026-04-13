// Canary token subsystem for detecting prompt leakage and goal hijacking.
//
// A canary token is a unique marker injected into prompts before sending them
// to an LLM. If the token appears in the LLM's response, it suggests that
// the model may have echoed hidden content — a potential signal of goal
// hijacking or prompt leakage, though not proof (the model might echo
// artifacts for other reasons, or middleware could reflect content).
//
// # Token Format
//
// Tokens use an HTML-comment-like format: <!--CANARY-<16 hex chars>-->
//
// This format was chosen because:
//   - Invisible to end users in most rendered contexts (HTML, Markdown)
//   - Preserved verbatim in raw text pipelines
//   - Unlikely to collide with legitimate content
//   - Easy to grep/search in logs
//
// # Limitations
//
// Canary tokens are a best-effort leak detection signal, not a guarantee:
//   - Absence of the canary in output does NOT prove the prompt is safe
//   - Some pipelines may strip HTML comments or transform the token
//   - An attacker-controlled LLM could be instructed to omit the canary
//   - The token only detects verbatim leakage, not paraphrased content
//
// For defense-in-depth, combine canary checks with Assess() scoring.
package idpishield

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// canaryPrefix and canarySuffix wrap the random token.
const (
	canaryPrefix = "<!--CANARY-"
	canarySuffix = "-->"
)

// CanaryResult is returned by CheckCanary and reports whether the injected
// canary token was detected in the LLM response.
type CanaryResult struct {
	// Token is the canary value that was originally injected into the prompt.
	Token string

	// Found is true when the canary token appears in the LLM response.
	// This suggests possible prompt leakage, but is not definitive proof.
	Found bool
}

// generateCanaryToken returns a cryptographically random canary token with
// the format:  <!--CANARY-<16 lowercase hex chars>-->
// 8 random bytes produce 16 hex characters, giving 2^64 unique values.
// Returns a non-nil error only if the system entropy source fails.
func generateCanaryToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return canaryPrefix + hex.EncodeToString(b) + canarySuffix, nil
}

// injectCanary appends the canary token on a new line at the end of prompt.
// Returns:
//   - injectedPrompt : original prompt with the token appended
//   - token          : the canary string the caller must hold for later checking
//   - err            : non-nil only if entropy generation fails
func injectCanary(prompt string) (injectedPrompt string, token string, err error) {
	token, err = generateCanaryToken()
	if err != nil {
		return prompt, "", err
	}
	return prompt + "\n" + token, token, nil
}

// checkCanary reports whether token is present in response.
// An empty token always returns Found=false to prevent false positives.
func checkCanary(response, token string) CanaryResult {
	if token == "" {
		return CanaryResult{Token: token, Found: false}
	}
	trimmedResponse := strings.TrimSpace(response)
	if trimmedResponse == "" {
		return CanaryResult{Token: token, Found: false}
	}
	return CanaryResult{
		Token: token,
		Found: strings.Contains(trimmedResponse, token),
	}
}
