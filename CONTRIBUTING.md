# Contributing to idpi-shield

Thank you for considering contributing to idpi-shield! This project aims to provide the best open-source defense against indirect prompt injection attacks.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch from `main`

## Development Setup

### Go Client

```bash
cd clients/go
go test ./...
go test -bench=. -benchmem
```

### Running Tests

All code changes must pass existing tests:

```bash
# Run all Go tests
cd clients/go
go test -v ./...

# Run benchmarks
go test -bench=. -benchmem

# Run with race detector
go test -race ./...
```

## Code Standards

### Go

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use `gofmt` for formatting (no exceptions)
- Run `go vet` before submitting
- Write table-driven tests
- Export only what's necessary — keep the public API small
- Zero external dependencies for client libraries (standard library only)

### All Languages

- Every client implementation must pass the conformance tests in `tests/compliance/test_vectors.json`
- Pattern definitions must mirror `spec/PATTERNS.md` exactly
- RiskResult must conform to `spec/RISK_RESULT.md`

## Adding Patterns

1. Add the pattern to `spec/PATTERNS.md` first (source of truth)
2. Implement in all client libraries (`patterns/builtin.*`)
3. Add a test vector to `tests/compliance/test_vectors.json`
4. Add example attack strings to the appropriate `tests/corpus/*.txt`

Pattern requirements:
- Must have a unique ID following the format: `{lang}-{category_abbrev}-{number}`
- Must include severity (1–5) with clear justification
- Must be tested against both attack and benign text to avoid false positives

## Pull Request Process

1. Keep PRs focused — one feature or fix per PR
2. Include tests for all new functionality
3. Update documentation if you change behavior
4. Ensure all CI checks pass
5. Request review from a maintainer

## Reporting Vulnerabilities

If you discover a security vulnerability, **do not open a public issue**. Instead, email the maintainers directly. We will respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
