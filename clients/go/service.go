package idpishield

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// serviceClient communicates with the idpi-shield Python service (Tier 2).
// Handles HTTP transport, serialization, timeouts, and graceful fallback.
type serviceClient struct {
	baseURL    string
	httpClient *http.Client
}

func newServiceClient(baseURL string, timeout time.Duration) *serviceClient {
	return &serviceClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// assessRequest is the JSON request body for POST /assess.
type assessRequest struct {
	Text string `json:"text"`
	URL  string `json:"url,omitempty"`
	Mode string `json:"mode"`
}

// assess sends text to the service for deep semantic analysis.
// Returns the service's RiskResult or an error (caller should fall back to local result).
func (s *serviceClient) assess(ctx context.Context, text, sourceURL, mode string) (*RiskResult, error) {
	reqBody := assessRequest{
		Text: text,
		URL:  sourceURL,
		Mode: mode,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("idpishield: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/assess", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("idpishield: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("idpishield: service request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("idpishield: service returned status %d", resp.StatusCode)
	}

	var result RiskResult
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return nil, fmt.Errorf("idpishield: decode response: %w", err)
	}

	result.Source = "service"

	// Ensure slices are never nil for JSON consistency
	if result.Patterns == nil {
		result.Patterns = []string{}
	}
	if result.Categories == nil {
		result.Categories = []string{}
	}

	return &result, nil
}
