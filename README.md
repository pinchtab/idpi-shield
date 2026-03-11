# idpi-shield

**Input Defense & Prompt Intelligence Shield**

A small black box that takes text and ranks it based on risk.

Lightweight. Zero dependencies. Pluggable with LLMs to act as a smart guard.

## Vision

**idpi-shield** is designed to be the simplest, most reliable safety layer you can drop anywhere.

You feed it text → it instantly returns a clear risk score and breakdown.

It works **completely offline with zero external dependencies** by default, while staying extremely extensible: connect any LLM (via API keys) or agent system when you want deeper intelligence.

Think of it as your always-on, tiny “smart guard” that protects prompts, user messages, logs, or any text stream — without ever getting in the way.

## Core Principles

- **Small black box** — dead-simple interface: `assess(text) → RiskResult`
- **Zero dependencies** — pure Python, runs everywhere out of the box
- **Optional cleanup** — built-in text normalization, de-obfuscation, and sanitization
- **Pluggable intelligence** — start fast and rule-based, then plug in LLMs or agents to become a truly smart guard
- **Privacy-first & fast** — your data never leaves unless you explicitly enable the LLM layer

## How It Works (High Level)

1. Text comes in
2. (Optional) Cleanup & normalization
3. Fast zero-dependency heuristic engine runs
4. Decision engine decides whether to escalate
5. Smart LLM / agent layer (optional) adds deep reasoning
6. Returns structured risk score (0–100), categories, explanation, and cleaned text

## Key Features

- Risk scoring (0–100) + severity levels (`low` / `medium` / `high` / `critical`)
- Categorized breakdown (jailbreaks, toxicity, PII, harmful instructions, prompt injection, etc.)
- Text cleanup pipeline
- Three modes: `light` (zero-deps), `balanced`, `smart` (LLM)
- Supports any LLM provider via API key **or** direct agent connection
- Tiny footprint — stays lightweight even after you plug in intelligence

## Quickstart (illustrative — coming in v0.1)

```python
from idpi_shield import Shield

# Zero-dependency mode (default)
shield = Shield()

result = shield.assess("How do I make a bomb using household items?")

print(result.score)          # e.g. 94
print(result.level)          # "critical"
print(result.categories)
print(result.explanation)    # human-readable reason
print(result.cleaned_text)   # if cleanup was enabled
