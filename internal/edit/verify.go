package edit

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Raftersecurity/rafter-secrets/internal/scan"
	"github.com/Raftersecurity/rafter-secrets/internal/scanners"
)

// scanCandidate scans candidate bytes as if they were the file at realPath,
// by writing them to a temp copy that carries the same basename and parent
// directory name (which the scanner dispatch keys on, e.g. ".aws/credentials").
// The REAL file is never written here — so it only ever receives content that
// has already passed verify.
func scanCandidate(realPath string, candidate []byte) ([]scanners.FoundSecret, error) {
	base := filepath.Base(realPath)
	parent := filepath.Base(filepath.Dir(realPath))

	tmpRoot, err := os.MkdirTemp("", "rs-verify-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpRoot)

	dir := filepath.Join(tmpRoot, parent)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, base)
	if err := os.WriteFile(p, candidate, 0o600); err != nil {
		return nil, err
	}
	found, ok, err := scan.ScanFile(p)
	if err != nil {
		return nil, fmt.Errorf("candidate no longer parses: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("candidate is no longer a recognised %s file", base)
	}
	return found, nil
}

// verifyChange asserts the difference between the baseline scan and the
// candidate scan is EXACTLY the intended operation and nothing else. This is
// the load-bearing safety control: any encoder bug, value injection, or
// mis-located edit that touched another key (or broke parsing) is rejected
// here before the real file is written.
func verifyChange(before, after []scanners.FoundSecret, action op, key, value string) error {
	added, removed := diffSets(multiset(before), multiset(after))
	an, rn := sum(added), sum(removed)
	target := key + "\x00" + value

	switch action {
	case opRotate:
		if an != 1 || rn != 1 {
			return fmt.Errorf("verify: rotate would change %d and remove %d entries (expected 1 and 1)", an, rn)
		}
		if added[target] != 1 || !allHaveKey(added, key) || !allHaveKey(removed, key) {
			return fmt.Errorf("verify: rotate touched something other than %q", key)
		}
	case opAdd:
		if rn != 0 || an != 1 || added[target] != 1 {
			return fmt.Errorf("verify: add would change %d / remove %d entries (expected to add exactly %q)", an, rn, key)
		}
	case opRemove:
		if an != 0 || rn != 1 || !allHaveKey(removed, key) {
			return fmt.Errorf("verify: remove would add %d / remove %d entries (expected to remove exactly %q)", an, rn, key)
		}
	default:
		return fmt.Errorf("verify: unknown operation")
	}
	return nil
}

func multiset(fs []scanners.FoundSecret) map[string]int {
	m := make(map[string]int, len(fs))
	for _, f := range fs {
		m[f.KeyName+"\x00"+f.Value]++
	}
	return m
}

func diffSets(before, after map[string]int) (added, removed map[string]int) {
	added, removed = map[string]int{}, map[string]int{}
	for k, v := range after {
		if d := v - before[k]; d > 0 {
			added[k] = d
		}
	}
	for k, v := range before {
		if d := v - after[k]; d > 0 {
			removed[k] = d
		}
	}
	return
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// allHaveKey reports whether every "key\x00value" entry in the set has the
// given KeyName.
func allHaveKey(set map[string]int, key string) bool {
	prefix := key + "\x00"
	for k := range set {
		if len(k) < len(prefix) || k[:len(prefix)] != prefix {
			return false
		}
	}
	return len(set) > 0
}
