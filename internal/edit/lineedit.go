package edit

import (
	"errors"
	"strings"
)

// Operation kinds.
type op int

const (
	opRotate op = iota // change an existing key's value
	opAdd              // add a new key
	opRemove           // delete an existing key
)

// Sentinel errors the engine maps to friendly messages / HTTP codes.
var (
	errUnrepresentable = errors.New("that value can't be stored safely in this file's format")
	errKeyNotFound     = errors.New("key not found in file")
	errKeyExists       = errors.New("key already exists in file")
)

// editor turns original file bytes into new file bytes for one operation.
// It does NO I/O — it's a pure transform, so it's trivially testable and the
// engine owns all the disk + safety machinery. line is a 1-based hint for
// line-based formats (which physical line the secret was observed on); it is
// ignored by structured editors.
type editor interface {
	apply(orig []byte, action op, key, value string, line int) ([]byte, error)
}

// lineEditor implements editor for KEY=VALUE line-based formats. keyOf
// identifies the key a content line assigns; render produces a replacement
// line (no newline). Everything else in the file is preserved byte-for-byte.
type lineEditor struct {
	keyOf  func(line string) (string, bool)
	render func(key, value string) (string, error)
}

func (e lineEditor) apply(orig []byte, action op, key, value string, line int) ([]byte, error) {
	lines, trailingNL := splitLines(orig)

	idx := -1
	// Prefer the hinted line if it actually assigns this key.
	if line >= 1 && line <= len(lines) {
		if k, ok := e.keyOf(lines[line-1]); ok && k == key {
			idx = line - 1
		}
	}
	if idx == -1 {
		for i, ln := range lines {
			if k, ok := e.keyOf(ln); ok && k == key {
				idx = i
				break
			}
		}
	}

	switch action {
	case opRotate:
		if idx == -1 {
			return nil, errKeyNotFound
		}
		newLine, err := e.render(key, value)
		if err != nil {
			return nil, err
		}
		lines[idx] = newLine
		return joinLines(lines, trailingNL), nil

	case opRemove:
		if idx == -1 {
			return nil, errKeyNotFound
		}
		lines = append(lines[:idx], lines[idx+1:]...)
		return joinLines(lines, trailingNL), nil

	case opAdd:
		if idx != -1 {
			return nil, errKeyExists
		}
		newLine, err := e.render(key, value)
		if err != nil {
			return nil, err
		}
		lines = append(lines, newLine)
		return joinLines(lines, true), nil
	}
	return nil, errors.New("edit: unknown operation")
}

// splitLines splits on \n into content lines (without the \n) and reports
// whether the input ended with a newline, so joinLines can reproduce the
// file's exact framing. An empty input is zero lines, no trailing newline.
func splitLines(b []byte) (lines []string, trailingNL bool) {
	if len(b) == 0 {
		return nil, false
	}
	s := string(b)
	trailingNL = strings.HasSuffix(s, "\n")
	if trailingNL {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n"), trailingNL
}

func joinLines(lines []string, trailingNL bool) []byte {
	out := strings.Join(lines, "\n")
	if trailingNL && len(lines) > 0 {
		out += "\n"
	}
	return []byte(out)
}

// ---- value encoders ---------------------------------------------------
//
// Encoders are best-effort: they pick the quoting that round-trips through
// this project's OWN scanner. Anything that can't round-trip is rejected
// here, and the engine's re-scan verify is the backstop — so the worst case
// is a clean "can't store that value", never a corrupted file.

func hasControl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == 0 {
			return true
		}
	}
	return false
}

// dotenvRender: KEY=value, picking bare / double / single quoting so the
// dotenv scanner reads the value back verbatim.
func dotenvRender(key, value string) (string, error) {
	if hasControl(value) {
		return "", errUnrepresentable
	}
	switch {
	case isBareSafe(value):
		return key + "=" + value, nil
	case !strings.Contains(value, `"`):
		return key + `="` + value + `"`, nil
	case !strings.Contains(value, `'`):
		return key + `='` + value + `'`, nil
	default:
		return "", errUnrepresentable
	}
}

// shellRender: export KEY='value'. Single quotes make the value inert when
// the rc file is sourced. A value containing a single quote can't round-trip
// our scanner's simple quote handling, so it's rejected.
func shellRender(key, value string) (string, error) {
	if hasControl(value) || strings.Contains(value, "'") {
		return "", errUnrepresentable
	}
	return "export " + key + "='" + value + "'", nil
}

// npmrcRender: key=value, unquoted. The npmrc scanner trims surrounding
// whitespace, so leading/trailing spaces can't round-trip and are rejected.
func npmrcRender(key, value string) (string, error) {
	if hasControl(value) || value != strings.TrimSpace(value) {
		return "", errUnrepresentable
	}
	return key + "=" + value, nil
}

// isBareSafe reports whether a value needs no quoting to round-trip through
// the dotenv scanner: no surrounding space, no quotes, and no " #" inline-
// comment sequence (which the scanner would treat as a comment).
func isBareSafe(value string) bool {
	if value == "" {
		return false // use explicit "" rather than a bare empty value
	}
	if value != strings.TrimSpace(value) {
		return false
	}
	// Quote anything with whitespace, quotes, or a '#': bare round-trips our
	// own scanner, but quoting keeps it safe if the .env is shell-sourced or
	// read by a stricter dotenv parser.
	if strings.ContainsAny(value, " \t\"'#") {
		return false
	}
	return true
}

// ---- key detectors (mirror the scanners; verify is the real check) ----

func dotenvKeyOf(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", false
	}
	if strings.HasPrefix(t, "export ") || strings.HasPrefix(t, "export\t") {
		t = strings.TrimSpace(t[len("export"):])
	}
	return keyBeforeEq(t)
}

func shellKeyOf(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", false
	}
	if !strings.HasPrefix(t, "export ") && !strings.HasPrefix(t, "export\t") {
		return "", false
	}
	return keyBeforeEq(strings.TrimSpace(t[len("export"):]))
}

func npmrcKeyOf(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "[") {
		return "", false
	}
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return "", false
	}
	return strings.TrimSpace(t[:eq]), true
}

func keyBeforeEq(t string) (string, bool) {
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return "", false
	}
	key := strings.TrimSpace(t[:eq])
	if !isEnvKey(key) {
		return "", false
	}
	return key, true
}

func isEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
