package edit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---- INI (AWS shared credentials), line-surgical ----------------------
//
// KeyName is "<profile>.<field>" (e.g. "default.aws_access_key_id"). We edit
// the physical line so comments, ordering, and other profiles are preserved.

type iniSectionEditor struct{}

func (iniSectionEditor) apply(orig []byte, action op, key, value string, _ int) ([]byte, error) {
	profile, field, ok := splitFirstDot(key)
	if !ok {
		return nil, errKeyNotFound
	}
	lines, trailingNL := splitLines(orig)

	header := "[" + profile + "]"
	secStart := -1
	for i, ln := range lines {
		if strings.TrimSpace(ln) == header {
			secStart = i
			break
		}
	}
	fieldIdx := -1
	if secStart >= 0 {
		for i := secStart + 1; i < len(lines); i++ {
			t := strings.TrimSpace(lines[i])
			if strings.HasPrefix(t, "[") {
				break // next section
			}
			if k, ok := iniKeyOf(t); ok && k == field {
				fieldIdx = i
				break
			}
		}
	}

	render := func() (string, error) {
		// INI inline comments start with # or ; — a value containing them
		// can't round-trip, so reject (verify would catch it regardless).
		if hasControl(value) || strings.ContainsAny(value, "#;") {
			return "", errUnrepresentable
		}
		return field + " = " + value, nil
	}

	switch action {
	case opRotate:
		if fieldIdx == -1 {
			return nil, errKeyNotFound
		}
		nl, err := render()
		if err != nil {
			return nil, err
		}
		lines[fieldIdx] = nl
		return joinLines(lines, trailingNL), nil
	case opRemove:
		if fieldIdx == -1 {
			return nil, errKeyNotFound
		}
		lines = append(lines[:fieldIdx], lines[fieldIdx+1:]...)
		return joinLines(lines, trailingNL), nil
	case opAdd:
		if fieldIdx != -1 {
			return nil, errKeyExists
		}
		nl, err := render()
		if err != nil {
			return nil, err
		}
		if secStart >= 0 {
			lines = append(lines[:secStart+1], append([]string{nl}, lines[secStart+1:]...)...)
		} else {
			lines = append(lines, header, nl)
		}
		return joinLines(lines, true), nil
	}
	return nil, errors.New("edit: unknown operation")
}

func iniKeyOf(t string) (string, bool) {
	if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return "", false
	}
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return "", false
	}
	return strings.TrimSpace(t[:eq]), true
}

// ---- JSON (docker config.json, claude settings.json) ------------------
//
// Parse → set/delete the nested key → re-marshal. Re-marshalling reformats
// the file (key order / whitespace), which is acceptable for these
// tool-managed configs; the verify round-trip guarantees only the target
// secret changed semantically.

type jsonEditor struct{ kind string }

func (e jsonEditor) apply(orig []byte, action op, key, value string, _ int) ([]byte, error) {
	root := map[string]any{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if err := json.Unmarshal(orig, &root); err != nil {
			return nil, err
		}
	}
	parent, field, err := e.locate(root, key, action == opAdd)
	if err != nil {
		return nil, err
	}
	_, present := parent[field]
	switch action {
	case opRotate:
		if !present {
			return nil, errKeyNotFound
		}
		parent[field] = value
	case opRemove:
		if !present {
			return nil, errKeyNotFound
		}
		delete(parent, field)
	case opAdd:
		if present {
			return nil, errKeyExists
		}
		parent[field] = value
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// locate resolves the parent map + leaf field name for a dotted key.
// docker keys are "<registry>.<auth|identitytoken>" (registry may contain
// dots); claude keys are a generic dotted path of object keys.
func (e jsonEditor) locate(root map[string]any, key string, create bool) (map[string]any, string, error) {
	if e.kind == "docker" {
		var field string
		switch {
		case strings.HasSuffix(key, ".auth"):
			field = "auth"
		case strings.HasSuffix(key, ".identitytoken"):
			field = "identitytoken"
		default:
			return nil, "", errKeyNotFound
		}
		registry := strings.TrimSuffix(key, "."+field)
		auths := descend(root, "auths", create)
		if auths == nil {
			return nil, "", errKeyNotFound
		}
		reg := descend(auths, registry, create)
		if reg == nil {
			return nil, "", errKeyNotFound
		}
		return reg, field, nil
	}
	// claude: walk the dotted path; the last segment is the field.
	segs := strings.Split(key, ".")
	cur := root
	for i := 0; i < len(segs)-1; i++ {
		cur = descend(cur, segs[i], create)
		if cur == nil {
			return nil, "", errKeyNotFound
		}
	}
	return cur, segs[len(segs)-1], nil
}

// descend returns the child map at key, creating it if create is set.
// Returns nil when the child is missing (and not created) or isn't a map.
func descend(m map[string]any, key string, create bool) map[string]any {
	if v, ok := m[key]; ok {
		if child, ok := v.(map[string]any); ok {
			return child
		}
		return nil // exists but not an object — refuse to descend
	}
	if !create {
		return nil
	}
	child := map[string]any{}
	m[key] = child
	return child
}

// ---- YAML (gh hosts.yml) ----------------------------------------------
//
// Shape is map[host]map[field]value. KeyName is "<host>.<field>" with field
// in a known set, so we split on the LAST dot (hosts contain dots, fields
// don't).

type yamlEditor struct{}

func (yamlEditor) apply(orig []byte, action op, key, value string, _ int) ([]byte, error) {
	root := map[string]map[string]any{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if err := yaml.Unmarshal(orig, &root); err != nil {
			return nil, err
		}
	}
	dot := strings.LastIndexByte(key, '.')
	if dot <= 0 || dot >= len(key)-1 {
		return nil, errKeyNotFound
	}
	host, field := key[:dot], key[dot+1:]

	hostMap, ok := root[host]
	if !ok {
		if action != opAdd {
			return nil, errKeyNotFound
		}
		hostMap = map[string]any{}
		root[host] = hostMap
	}
	_, present := hostMap[field]
	switch action {
	case opRotate:
		if !present {
			return nil, errKeyNotFound
		}
		hostMap[field] = value
	case opRemove:
		if !present {
			return nil, errKeyNotFound
		}
		delete(hostMap, field)
	case opAdd:
		if present {
			return nil, errKeyExists
		}
		hostMap[field] = value
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func splitFirstDot(s string) (a, b string, ok bool) {
	i := strings.IndexByte(s, '.')
	if i <= 0 || i >= len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
