package envfile

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/tk-425/kenv/internal/vault"
)

var (
	errInvalidAssignment      = errors.New("expected KEY=value assignment")
	errUnsupportedExport      = errors.New("unsupported export syntax")
	errMissingClosingQuote    = errors.New("missing closing quote")
	errTrailingCharacters     = errors.New("unexpected trailing characters after quoted value")
	errUnsupportedEscape      = errors.New("unsupported escape sequence in double-quoted value")
	errInvalidKey             = errors.New("invalid key")
	errDuplicateKey           = errors.New("duplicate key")
	errMultilineValueRejected = errors.New("multiline values are not supported")
)

type Entry struct {
	Key   string
	Value string
	Line  int
}

type Warning struct {
	Key     string
	Line    int
	Message string
}

type File struct {
	Entries               []Entry
	Values                map[string]string
	PlaceholderCandidates []Entry
	Warnings              []Warning
}

type SyntaxError struct {
	Path   string
	Line   int
	Reason string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("invalid env syntax at %s:%d: %s", e.Path, e.Line, e.Reason)
}

func ParseFile(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read env file %s: %w", path, err)
	}

	return Parse(path, string(data))
}

func Parse(path, content string) (File, error) {
	content = string(stripUTF8BOM([]byte(content)))

	result := File{
		Entries:               []Entry{},
		Values:                make(map[string]string),
		PlaceholderCandidates: []Entry{},
		Warnings:              []Warning{},
	}

	seenKeys := make(map[string]int)
	for index, rawLine := range strings.Split(content, "\n") {
		lineNo := index + 1
		line := strings.TrimSuffix(rawLine, "\r")
		trimmed := trimHorizontalSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if isUnsupportedExport(trimmed) {
			return File{}, syntaxError(path, lineNo, errUnsupportedExport.Error())
		}

		key, value, err := parseAssignmentLine(trimmed)
		if err != nil {
			return File{}, syntaxError(path, lineNo, err.Error())
		}
		if !isValidKey(key) {
			return File{}, syntaxError(path, lineNo, fmt.Sprintf("%s %q", errInvalidKey.Error(), key))
		}
		if firstLine, exists := seenKeys[key]; exists {
			return File{}, syntaxError(path, lineNo, fmt.Sprintf("%s %q (first defined at line %d)", errDuplicateKey.Error(), key, firstLine))
		}
		seenKeys[key] = lineNo

		entry := Entry{Key: key, Value: value, Line: lineNo}
		result.Entries = append(result.Entries, entry)
		result.Values[key] = value

		if vault.IsPlaceholder(value) {
			result.PlaceholderCandidates = append(result.PlaceholderCandidates, entry)
			continue
		}
		if looksLikePlaintextSecretKey(key) {
			result.Warnings = append(result.Warnings, Warning{
				Key:     key,
				Line:    lineNo,
				Message: fmt.Sprintf("warning: %s appears to contain a plaintext secret; use a kenv placeholder instead", key),
			})
		}
	}

	return result, nil
}

func parseAssignmentLine(line string) (string, string, error) {
	eqIndex := strings.IndexByte(line, '=')
	if eqIndex < 0 {
		return "", "", errInvalidAssignment
	}

	key := trimHorizontalSpace(line[:eqIndex])
	if key == "" {
		return "", "", fmt.Errorf("%w: empty key", errInvalidKey)
	}

	rawValue := trimLeadingHorizontalSpace(line[eqIndex+1:])
	if rawValue == "" {
		return key, "", nil
	}

	switch rawValue[0] {
	case '\'':
		value, trailing, err := parseSingleQuotedValue(rawValue)
		if err != nil {
			return "", "", err
		}
		if trimHorizontalSpace(trailing) != "" {
			return "", "", errTrailingCharacters
		}
		return key, value, nil
	case '"':
		value, trailing, err := parseDoubleQuotedValue(rawValue)
		if err != nil {
			return "", "", err
		}
		if trimHorizontalSpace(trailing) != "" {
			return "", "", errTrailingCharacters
		}
		return key, value, nil
	default:
		if strings.ContainsRune(rawValue, '\r') || strings.ContainsRune(rawValue, '\n') {
			return "", "", errMultilineValueRejected
		}
		return key, trimHorizontalSpace(rawValue), nil
	}
}

func parseSingleQuotedValue(input string) (string, string, error) {
	end := strings.IndexByte(input[1:], '\'')
	if end < 0 {
		return "", "", errMissingClosingQuote
	}

	closing := end + 1
	return input[1:closing], input[closing+1:], nil
}

func parseDoubleQuotedValue(input string) (string, string, error) {
	var builder strings.Builder
	for i := 1; i < len(input); i++ {
		switch input[i] {
		case '"':
			return builder.String(), input[i+1:], nil
		case '\\':
			if i+1 >= len(input) {
				return "", "", errMissingClosingQuote
			}
			escaped, ok := decodeEscape(input[i+1])
			if !ok {
				return "", "", errUnsupportedEscape
			}
			builder.WriteByte(escaped)
			i++
		case '\r', '\n':
			return "", "", errMultilineValueRejected
		default:
			builder.WriteByte(input[i])
		}
	}

	return "", "", errMissingClosingQuote
}

func decodeEscape(next byte) (byte, bool) {
	switch next {
	case '\\':
		return '\\', true
	case '"':
		return '"', true
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	default:
		return 0, false
	}
}

func looksLikePlaintextSecretKey(key string) bool {
	upper := strings.ToUpper(key)
	markers := []string{"KEY", "TOKEN", "SECRET", "PASSWORD"}
	for _, marker := range markers {
		if strings.Contains(upper, marker) {
			return true
		}
	}

	return false
}

func isValidKey(key string) bool {
	for i, r := range key {
		if i == 0 {
			if !(r == '_' || isASCIILetter(r)) {
				return false
			}
			continue
		}
		if !(r == '_' || isASCIILetter(r) || isASCIIDigit(r)) {
			return false
		}
	}

	return key != ""
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isASCIIDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func isUnsupportedExport(line string) bool {
	return strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t")
}

func trimHorizontalSpace(value string) string {
	return strings.Trim(value, " \t")
}

func trimLeadingHorizontalSpace(value string) string {
	return strings.TrimLeft(value, " \t")
}

func stripUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && utf8.Valid(data[:3]) && string(data[:3]) == "\ufeff" {
		return data[3:]
	}

	return data
}

func syntaxError(path string, line int, reason string) error {
	return &SyntaxError{
		Path:   path,
		Line:   line,
		Reason: reason,
	}
}
