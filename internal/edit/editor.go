package edit

import (
	"fmt"

	"github.com/Raftersecurity/rafter-secrets/internal/scan"
)

// errUnsupportedFormat is returned for a recognised source whose format
// doesn't yet have an editor (it stays read-only).
type errUnsupportedFormat struct{ kind string }

func (e errUnsupportedFormat) Error() string {
	return fmt.Sprintf("editing %s files isn't supported yet", e.kind)
}

// editorFor returns the format-aware editor for a path, or an error if the
// path isn't a recognised source or its format isn't editable yet.
func editorFor(path string) (editor, error) {
	kind, ok := scan.SourceKind(path)
	if !ok {
		return nil, fmt.Errorf("%s is not a recognised secret file", path)
	}
	switch kind {
	case scan.KindDotenv:
		return lineEditor{keyOf: dotenvKeyOf, render: dotenvRender}, nil
	case scan.KindShellRC:
		return lineEditor{keyOf: shellKeyOf, render: shellRender}, nil
	case scan.KindNpmrc:
		return lineEditor{keyOf: npmrcKeyOf, render: npmrcRender}, nil
	case scan.KindAWS:
		return iniSectionEditor{}, nil
	case scan.KindDocker, scan.KindClaude:
		return jsonEditor{kind: kind}, nil
	case scan.KindGh:
		return yamlEditor{}, nil
	default:
		return nil, errUnsupportedFormat{kind: kind}
	}
}
