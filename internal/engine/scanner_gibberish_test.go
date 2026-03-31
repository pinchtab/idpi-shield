package engine

import (
	"strings"
	"testing"
)

func TestScanGibberish_ConsonantClusters(t *testing.T) {
	res := scanGibberish("xkqpvzmwbfjd rtksplvnhq")
	if !res.IsGibberish {
		t.Fatalf("expected gibberish detection, got %+v", res)
	}
}

func TestScanGibberish_NormalEnglish(t *testing.T) {
	res := scanGibberish("This is a normal paragraph describing a product release with clear natural language.")
	if res.IsGibberish {
		t.Fatalf("expected normal English not to be gibberish, got %+v", res)
	}
}

func TestScanGibberish_CodeSnippetSkipped(t *testing.T) {
	code := "func main() { var x = 1; return }"
	res := scanGibberish(code)
	if res.IsGibberish || res.HasHighEntropyBlock {
		t.Fatalf("expected code snippet to be skipped, got %+v", res)
	}
}

func TestScanGibberish_HighEntropyToken(t *testing.T) {
	res := scanGibberish("aB3xK9mP2qR7nL4wS1tV6yH8uJ0cD5fQ")
	if !res.HasHighEntropyBlock {
		t.Fatalf("expected high entropy block detection, got %+v", res)
	}
}

func TestScanGibberish_URLSkipped(t *testing.T) {
	res := scanGibberish("https://example.com/path?q=abc")
	if res.IsGibberish || res.HasHighEntropyBlock {
		t.Fatalf("expected URL input to be skipped, got %+v", res)
	}
}

func TestScanGibberish_HexStringNotGibberish(t *testing.T) {
	res := scanGibberish("deadbeef1234cafe5678")
	if res.IsGibberish {
		t.Fatalf("expected hex payload not to be flagged as gibberish, got %+v", res)
	}
}

func TestScanGibberish_ShortInputGuard(t *testing.T) {
	res := scanGibberish("xkqpvzmwbfjd")
	if res.IsGibberish || res.HasHighEntropyBlock || res.GibberishRatio != 0 {
		t.Fatalf("expected short-input guard to keep result clean, got %+v", res)
	}
}

func TestScanGibberish_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "whitespace", input: "   \n\t  "},
		{name: "very long", input: strings.Repeat("clear human sentence with common vocabulary ", 500)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := scanGibberish(tt.input)
			if res.IsGibberish || res.HasHighEntropyBlock || res.GibberishRatio != 0 {
				t.Fatalf("expected clean edge-case result, got %+v", res)
			}
		})
	}
}
