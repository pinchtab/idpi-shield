package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	idpi "github.com/pinchtab/idpi-shield"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage(os.Stdout)
		return
	}

	if os.Args[1] != "scan" {
		log.Printf("unknown command: %s\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}

	if err := runScan(os.Args[2:]); err != nil {
		log.Printf("scan failed: %v", err)
		os.Exit(2)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	mode := fs.String("mode", "balanced", "analysis mode: fast|balanced|deep")
	domains := fs.String("domains", "", "comma-separated allowlist domains")
	url := fs.String("url", "", "source URL for domain checks")
	strict := fs.Bool("strict", false, "enable strict mode (block >= 40)")

	if err := fs.Parse(args); err != nil {
		printUsage(os.Stderr)
		return err
	}

	remaining := fs.Args()
	text, err := readInput(remaining)
	if err != nil {
		return err
	}

	shield := idpi.New(idpi.Config{
		Mode:           idpi.ParseMode(*mode),
		AllowedDomains: parseDomains(*domains),
		StrictMode:     *strict,
	})

	result := shield.Assess(text, *url)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}

	if result.Blocked {
		os.Exit(1)
	}

	return nil
}

func readInput(args []string) (string, error) {
	if len(args) > 1 {
		return "", fmt.Errorf("scan accepts at most one positional input path")
	}

	if len(args) == 1 && args[0] != "-" {
		b, err := os.ReadFile(args[0])
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input provided; pass a file path or pipe stdin")
	}

	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseDomains(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	domains := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}
	return domains
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "idpi-shield CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  idpi-shield scan [file|-] --mode balanced --domains example.com,google.com")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  scan    Assess input from file path or stdin and emit JSON risk result")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "scan flags:")
	fmt.Fprintln(w, "  --mode      fast|balanced|deep (default: balanced)")
	fmt.Fprintln(w, "  --domains   comma-separated allowed domains")
	fmt.Fprintln(w, "  --url       source URL for domain allowlist checks")
	fmt.Fprintln(w, "  --strict    block at score >= 40 instead of >= 60")
}
