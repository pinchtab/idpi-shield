package idpishield

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalizer handles Unicode normalization for defeating obfuscation attacks.
// Zero external dependencies — implements focused normalization targeting
// known attack vectors: homoglyphs, zero-width characters, full-width chars,
// and whitespace abuse.
type normalizer struct{}

func newNormalizer() *normalizer {
	return &normalizer{}
}

// Normalize applies the full normalization pipeline to input text.
// Returns the normalized string suitable for pattern matching.
func (n *normalizer) Normalize(text string) string {
	if len(text) == 0 {
		return text
	}

	// Pipeline order matters:
	// 1. Strip zero-width / invisible characters (they split words)
	// 2. Map full-width characters to ASCII equivalents
	// 3. Map homoglyphs (Cyrillic → Latin, etc.)
	// 4. Collapse whitespace (tabs, multiple spaces → single space)
	// 5. Trim leading/trailing whitespace

	var buf strings.Builder
	buf.Grow(len(text))

	prevSpace := false
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		i += size

		if r == utf8.RuneError && size == 1 {
			continue // skip invalid UTF-8 bytes
		}

		// Step 1: Strip invisible characters
		if isInvisible(r) {
			continue
		}

		// Step 2: Full-width ASCII → standard ASCII (U+FF01–U+FF5E → U+0021–U+007E)
		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFF01 + 0x0021
		}

		// Step 3: Homoglyph mapping
		if mapped, ok := homoglyphMap[r]; ok {
			r = mapped
		}

		// Step 4: Collapse whitespace
		if unicode.IsSpace(r) {
			if !prevSpace {
				buf.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false

		buf.WriteRune(r)
	}

	return strings.TrimSpace(buf.String())
}

// isInvisible returns true for zero-width and invisible Unicode characters
// commonly used to obfuscate attack strings.
func isInvisible(r rune) bool {
	switch r {
	case
		'\u200B', // Zero Width Space
		'\u200C', // Zero Width Non-Joiner
		'\u200D', // Zero Width Joiner
		'\u200E', // Left-to-Right Mark
		'\u200F', // Right-to-Left Mark
		'\uFEFF', // BOM / Zero Width No-Break Space
		'\u2060', // Word Joiner
		'\u2061', // Function Application
		'\u2062', // Invisible Times
		'\u2063', // Invisible Separator
		'\u2064', // Invisible Plus
		'\u180E', // Mongolian Vowel Separator
		'\u00AD', // Soft Hyphen
		'\u034F', // Combining Grapheme Joiner
		'\u061C', // Arabic Letter Mark
		'\u115F', // Hangul Choseong Filler
		'\u1160', // Hangul Jungseong Filler
		'\u17B4', // Khmer Vowel Inherent Aq
		'\u17B5', // Khmer Vowel Inherent Aa
		'\uFFA0', // Halfwidth Hangul Filler
		'\u2800': // Braille Pattern Blank
		return true
	}

	// Unicode category Cf (Format characters) — catch remaining invisible chars
	// but exclude common ones we want to keep (like \t, \n which are handled as whitespace)
	if unicode.Is(unicode.Cf, r) {
		return true
	}

	return false
}

// homoglyphMap maps visually similar Unicode characters to their ASCII equivalents.
// Focuses on characters commonly used in prompt injection obfuscation.
var homoglyphMap = map[rune]rune{
	// Cyrillic lowercase → Latin lowercase
	'\u0430': 'a', // а
	'\u0435': 'e', // е
	'\u0456': 'i', // і (Ukrainian)
	'\u043E': 'o', // о
	'\u0440': 'p', // р
	'\u0441': 'c', // с
	'\u0443': 'y', // у
	'\u0455': 's', // ѕ (Macedonian)
	'\u0458': 'j', // ј (Serbian)
	'\u04BB': 'h', // һ
	'\u0501': 'd', // ԁ

	// Cyrillic uppercase → Latin uppercase
	'\u0410': 'A', // А
	'\u0412': 'B', // В
	'\u0421': 'C', // С
	'\u0415': 'E', // Е
	'\u041D': 'H', // Н
	'\u0406': 'I', // І (Ukrainian)
	'\u041A': 'K', // К
	'\u041C': 'M', // М
	'\u041E': 'O', // О
	'\u0420': 'P', // Р
	'\u0405': 'S', // Ѕ (Macedonian)
	'\u0422': 'T', // Т
	'\u0425': 'X', // Х

	// Greek → Latin
	'\u03B1': 'a', // α
	'\u03B5': 'e', // ε
	'\u03B9': 'i', // ι
	'\u03BF': 'o', // ο
	'\u03C1': 'p', // ρ (visually similar)
	'\u0391': 'A', // Α
	'\u0392': 'B', // Β
	'\u0395': 'E', // Ε
	'\u0397': 'H', // Η
	'\u0399': 'I', // Ι
	'\u039A': 'K', // Κ
	'\u039C': 'M', // Μ
	'\u039D': 'N', // Ν
	'\u039F': 'O', // Ο
	'\u03A1': 'P', // Ρ
	'\u03A4': 'T', // Τ
	'\u03A7': 'X', // Χ
	'\u03A5': 'Y', // Υ
	'\u0396': 'Z', // Ζ

	// Common mathematical/typographic lookalikes
	'\u2010': '-', // Hyphen
	'\u2011': '-', // Non-Breaking Hyphen
	'\u2012': '-', // Figure Dash
	'\u2013': '-', // En Dash
	'\u2014': '-', // Em Dash
	'\u2018': '\'', // Left Single Quotation
	'\u2019': '\'', // Right Single Quotation
	'\u201C': '"',  // Left Double Quotation
	'\u201D': '"',  // Right Double Quotation
	'\u2024': '.',  // One Dot Leader
	'\u2025': '.',  // Two Dot Leader (approximation)
	'\u2039': '<',  // Single Left-Pointing Angle Quotation
	'\u203A': '>',  // Single Right-Pointing Angle Quotation
	'\u2044': '/',  // Fraction Slash
	'\u2215': '/',  // Division Slash
	'\u2236': ':',  // Ratio

	// Subscript/superscript digits → regular digits
	'\u2070': '0',
	'\u00B9': '1',
	'\u00B2': '2',
	'\u00B3': '3',
	'\u2074': '4',
	'\u2075': '5',
	'\u2076': '6',
	'\u2077': '7',
	'\u2078': '8',
	'\u2079': '9',
	'\u2080': '0',
	'\u2081': '1',
	'\u2082': '2',
	'\u2083': '3',
	'\u2084': '4',
	'\u2085': '5',
	'\u2086': '6',
	'\u2087': '7',
	'\u2088': '8',
	'\u2089': '9',
}
