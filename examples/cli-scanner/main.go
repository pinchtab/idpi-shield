// cli-scanner: A command-line tool to scan text for prompt injection attacks
// using the idpi-shield Go library.
//
// Usage:
//
//	echo "Ignore all previous instructions" | go run main.go
//	go run main.go -text "your text here"
//	go run main.go -text "your text here" -strict
//	go run main.go -text "your text here" -mode light
//	go run main.go -interactive
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	idpi "github.com/idpi-shield/idpi-shield-go"
)

func main() {
	// Flags
	text        := flag.String("text", "", "Text to scan (omit to read from stdin)")
	mode        := flag.String("mode", "balanced", "Analysis mode: light, balanced, smart")
	strict      := flag.Bool("strict", false, "Enable strict mode (blocks at score >= 40)")
	jsonOut     := flag.Bool("json", false, "Output as JSON")
	interactive := flag.Bool("interactive", false, "Interactive mode: scan lines as you type")
	domains     := flag.String("domains", "", "Comma-separated allowed domains (e.g. 'example.com,*.trusted.org')")
	flag.Parse()

	// Build allowlist
	var allowedDomains []string
	if *domains != "" {
		for _, d := range strings.Split(*domains, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				allowedDomains = append(allowedDomains, d)
			}
		}
	}

	// Create client
	client := idpi.New(idpi.Config{
		Mode:           idpi.ParseMode(*mode),
		StrictMode:     *strict,
		AllowedDomains: allowedDomains,
	})

	// Interactive mode
	if *interactive {
		runInteractive(client, *jsonOut)
		return
	}

	// Text from flag
	if *text != "" {
		scan(client, *text, *jsonOut)
		return
	}

	// Text from stdin (pipe)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
			os.Exit(1)
		}
		scan(client, strings.TrimSpace(string(data)), *jsonOut)
		return
	}

	// No input provided
	fmt.Println("IDPI Shield CLI Scanner")
	fmt.Println("=======================")
	fmt.Println("Usage:")
	fmt.Println("  echo 'text' | go run main.go")
	fmt.Println("  go run main.go -text 'your text here'")
	fmt.Println("  go run main.go -interactive")
	fmt.Println("  go run main.go -text 'text' -strict -mode balanced -json")
}

func scan(client *idpi.Client, text string, asJSON bool) {
	start := time.Now()
	result := client.Scan(text)
	elapsed := time.Since(start)

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	printResult(text, result, elapsed)

	// Exit code signals threat for scripting: 0=safe, 1=threat
	if result.Blocked {
		os.Exit(1)
	}
}

func printResult(text string, result idpi.RiskResult, elapsed time.Duration) {
	// Color codes
	const (
		reset  = "\033[0m"
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		cyan   = "\033[36m"
		bold   = "\033[1m"
	)

	levelColor := green
	switch result.Level {
	case idpi.LevelLow:
		levelColor = cyan
	case idpi.LevelMedium:
		levelColor = yellow
	case idpi.LevelHigh, idpi.LevelCritical:
		levelColor = red
	}

	fmt.Println()
	fmt.Printf("%s╔══════════════════════════════════════════════════╗%s\n", bold, reset)
	if result.Blocked {
		fmt.Printf("%s║         ⛔  IDPI SHIELD — BLOCKED                 ║%s\n", red+bold, reset)
	} else if result.Threat {
		fmt.Printf("%s║         ⚠️   IDPI SHIELD — THREAT DETECTED          ║%s\n", yellow+bold, reset)
	} else {
		fmt.Printf("%s║         ✅  IDPI SHIELD — CLEAN                    ║%s\n", green+bold, reset)
	}
	fmt.Printf("%s╚══════════════════════════════════════════════════╝%s\n", bold, reset)

	fmt.Println()
	fmt.Printf("  %sScore:%s      %s%d/100%s\n", bold, reset, levelColor, result.Score, reset)
	fmt.Printf("  %sLevel:%s      %s%s%s\n", bold, reset, levelColor+bold, strings.ToUpper(string(result.Level)), reset)
	fmt.Printf("  %sBlocked:%s    %v\n", bold, reset, result.Blocked)
	fmt.Printf("  %sSource:%s     %s\n", bold, reset, result.Source)
	fmt.Printf("  %sTime:%s       %v\n", bold, reset, elapsed.Round(time.Microsecond))

	if result.Threat {
		fmt.Printf("  %sReason:%s     %s\n", bold, reset, result.Reason)

		if len(result.Categories) > 0 {
			fmt.Printf("  %sCategories:%s %s\n", bold, reset, strings.Join(result.Categories, ", "))
		}
		if len(result.Patterns) > 0 {
			fmt.Printf("  %sPatterns:%s   %s\n", bold, reset, strings.Join(result.Patterns, ", "))
		}
	}

	// Show input snippet (truncated for readability)
	snippet := text
	if len(snippet) > 100 {
		snippet = snippet[:97] + "..."
	}
	fmt.Printf("  %sInput:%s      %q\n", bold, reset, snippet)
	fmt.Println()
}

func runInteractive(client *idpi.Client, asJSON bool) {
	fmt.Println("IDPI Shield — Interactive Scanner")
	fmt.Println("Type text and press Enter to scan. Ctrl+C to quit.")
	fmt.Println("────────────────────────────────────────────────────")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("\n> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		start := time.Now()
		result := client.Scan(line)
		elapsed := time.Since(start)

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)
		} else {
			printResult(line, result, elapsed)
		}
	}
}
