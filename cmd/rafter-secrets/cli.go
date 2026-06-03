package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Raftersecurity/rafter-secrets/internal/edit"
	"github.com/Raftersecurity/rafter-secrets/internal/scan"
	"github.com/Raftersecurity/rafter-secrets/internal/storage"
)

// subcommands lists the CLI verbs. If os.Args[1] is one of these, the binary
// runs as a CLI; otherwise it launches the local web UI (runUI).
var subcommands = map[string]func([]string) int{
	"scan":    cmdScan,
	"list":    cmdList,
	"show":    cmdShow,
	"reveal":  cmdReveal,
	"rotate":  cmdRotate,
	"add":     cmdAdd,
	"rm":      cmdRemove,
	"undo":    cmdUndo,
	"history": cmdHistory,
	"help":    cmdHelp,
}

// dispatchCLI runs the matching subcommand. ok is false when args[0] isn't a
// subcommand, so main() falls through to launching the UI.
func dispatchCLI(args []string) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "-h", "--help":
		return cmdHelp(nil), true
	}
	fn, found := subcommands[args[0]]
	if !found {
		return 0, false
	}
	return fn(args[1:]), true
}

const usage = `Rafter Secrets — see and manage the secrets on your machine.

Usage:
  rafter-secrets [command] [flags]

Commands:
  (none)            Launch the local web app (default)
  scan              Scan your configured locations and update the inventory
  list              List tracked secrets
  show <key>        Show one secret: where it lives, projects, status
  reveal <key>      Print a secret's current value (reads it from disk)
  rotate <key>      Replace a secret's value everywhere it appears
  add <key>         Add a new secret into a file
  rm <key>          Remove a secret from where it appears
  undo [op-id]      Undo the last edit (or a specific operation)
  history           Show the edit history

Editing reads the new value from stdin (so it never appears in your shell
history or process list). Edits preview by default; pass --yes to apply.
Every edit is backed up and can be undone.

Global flags:
  --json            Machine-readable JSON output (for agents/scripts)

Examples:
  rafter-secrets list --json
  printf 'sk_live_new' | rafter-secrets rotate STRIPE_LIVE_KEY --yes
  rafter-secrets undo
`

func cmdHelp(_ []string) int { fmt.Print(usage); return 0 }

// parseArgs parses flags that may appear before OR after positional args
// (Go's flag package stops at the first positional). It repeatedly parses,
// peeling off leading positionals, so `rotate KEY --yes` works as expected.
func parseArgs(fs *flag.FlagSet, args []string) (positionals []string, err error) {
	for {
		if err = fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positionals, nil
		}
		positionals = append(positionals, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// arg0 returns the first positional or "".
func arg0(pos []string) string {
	if len(pos) > 0 {
		return pos[0]
	}
	return ""
}

// ---- shared plumbing --------------------------------------------------

type cliEnv struct {
	storePath string
	doc       *storage.Global
	json      bool
}

func loadEnv(jsonOut bool) (*cliEnv, error) {
	sp, err := storage.DefaultPath()
	if err != nil {
		return nil, err
	}
	doc, err := storage.Load(sp)
	if err != nil {
		return nil, err
	}
	return &cliEnv{storePath: sp, doc: doc, json: jsonOut}, nil
}

func (e *cliEnv) engine() *edit.Engine {
	return edit.New(filepath.Dir(e.storePath), canonRoots(e.doc.ScanConfig.Roots))
}

// findSecret resolves a key (or --id) to a single secret. It errors with a
// helpful message when a bare key is ambiguous across multiple secrets.
func (e *cliEnv) findSecret(key, id string) (*storage.Secret, error) {
	var matches []*storage.Secret
	for i := range e.doc.Secrets {
		s := &e.doc.Secrets[i]
		if id != "" {
			if s.ID == id {
				return s, nil
			}
			continue
		}
		if s.KeyName == key {
			matches = append(matches, s)
		}
	}
	switch {
	case id != "":
		return nil, fmt.Errorf("no secret with id %q", id)
	case len(matches) == 0:
		return nil, fmt.Errorf("no secret named %q (try: rafter-secrets list)", key)
	case len(matches) > 1:
		return nil, fmt.Errorf("%q matches %d secrets — pass --id to pick one", key, len(matches))
	default:
		return matches[0], nil
	}
}

// editTargets returns the editable file locations of a secret (file sources
// only — never keystore, manual, or source-code entries).
func editTargets(s *storage.Secret) []edit.Target {
	var ts []edit.Target
	for _, f := range s.FoundIn {
		if f.Path == "" || f.SourceType == storage.SourceManual || f.SourceType == storage.SourceKeystore {
			continue
		}
		ts = append(ts, edit.Target{Path: f.Path, Line: f.Line})
	}
	return ts
}

func canonRoots(in []string) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			out = append(out, real)
		}
	}
	return out
}

// rescanAfterEdit re-scans and persists so the inventory reflects the new
// values. Best-effort: an edit already succeeded; a stale store self-heals
// on the next scan.
func (e *cliEnv) rescanAfterEdit() {
	if _, err := scan.Run(context.Background(), e.doc, e.doc.ScanConfig); err == nil {
		_ = storage.Save(e.storePath, e.doc)
	}
}

// readValue reads a secret value: from --value if set, else from stdin (so
// it stays out of argv / shell history).
func readValue(valFlag string, stdin io.Reader) (string, error) {
	if valFlag != "" {
		return valFlag, nil
	}
	b, err := io.ReadAll(io.LimitReader(stdin, 64*1024+1))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func fail(jsonOut bool, code int, msg string) int {
	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": msg})
	} else {
		fmt.Fprintln(os.Stderr, "rafter-secrets: "+msg)
	}
	return code
}

func emit(v any) int {
	_ = json.NewEncoder(os.Stdout).Encode(v)
	return 0
}

// ---- commands ---------------------------------------------------------

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	res, err := scan.Run(context.Background(), env.doc, env.doc.ScanConfig)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	_ = storage.Save(env.storePath, env.doc)
	if *jsonOut {
		return emit(map[string]any{"ok": true, "files_scanned": res.FilesScanned, "secrets": len(env.doc.Secrets)})
	}
	fmt.Printf("Scanned %d file(s); %d secret(s) tracked.\n", res.FilesScanned, len(env.doc.Secrets))
	return 0
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	if *jsonOut {
		out := []map[string]any{}
		for _, s := range env.doc.Secrets {
			files := []string{}
			for _, f := range s.FoundIn {
				if f.Path != "" {
					files = append(files, f.Path)
				}
			}
			out = append(out, map[string]any{"id": s.ID, "key": s.KeyName, "files": files, "projects": s.Annotation.Tags, "stale": s.Annotation.Stale})
		}
		return emit(map[string]any{"ok": true, "secrets": out})
	}
	if len(env.doc.Secrets) == 0 {
		fmt.Println("No secrets tracked yet. Run: rafter-secrets scan")
		return 0
	}
	keys := make([]string, len(env.doc.Secrets))
	for i, s := range env.doc.Secrets {
		n := 0
		for _, f := range s.FoundIn {
			if f.Path != "" {
				n++
			}
		}
		keys[i] = fmt.Sprintf("%-32s %d location(s)", s.KeyName, n)
	}
	sort.Strings(keys)
	fmt.Println(strings.Join(keys, "\n"))
	return 0
}

func cmdShow(args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	id := fs.String("id", "", "secret id (disambiguate)")
	pos, perr := parseArgs(fs, args)
	if perr != nil {
		return 2
	}
	if len(pos) < 1 && *id == "" {
		return fail(*jsonOut, 2, "usage: rafter-secrets show <key>")
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	s, err := env.findSecret(arg0(pos), *id)
	if err != nil {
		return fail(*jsonOut, 2, err.Error())
	}
	if *jsonOut {
		return emit(map[string]any{"ok": true, "secret": s})
	}
	fmt.Printf("%s\n  id:        %s\n  projects:  %s\n", s.KeyName, s.ID, strings.Join(s.Annotation.Tags, ", "))
	for _, f := range s.FoundIn {
		if f.Path != "" {
			fmt.Printf("  found in:  %s%s\n", f.Path, lineSuffix(f.Line))
		}
	}
	return 0
}

func lineSuffix(line int) string {
	if line > 0 {
		return fmt.Sprintf(":%d", line)
	}
	return ""
}

func cmdReveal(args []string) int {
	fs := flag.NewFlagSet("reveal", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	id := fs.String("id", "", "secret id")
	pos, perr := parseArgs(fs, args)
	if perr != nil {
		return 2
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	s, err := env.findSecret(arg0(pos), *id)
	if err != nil {
		return fail(*jsonOut, 2, err.Error())
	}
	for _, f := range s.FoundIn {
		if f.Path == "" || f.SourceType == storage.SourceManual {
			continue
		}
		v, err := scan.ResolveValue(f, s.KeyName)
		if err != nil {
			continue
		}
		if *jsonOut {
			return emit(map[string]any{"ok": true, "key": s.KeyName, "value": v})
		}
		fmt.Println(v)
		return 0
	}
	return fail(*jsonOut, 2, "no readable value for "+s.KeyName)
}

func cmdRotate(args []string) int { return editCmd("rotate", args) }
func cmdRemove(args []string) int { return editCmd("rm", args) }

func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	value := fs.String("value", "", "value (else read from stdin)")
	file := fs.String("file", "", "file to add the secret into (required)")
	yes := fs.Bool("yes", false, "apply (default previews)")
	pos, perr := parseArgs(fs, args)
	if perr != nil {
		return 2
	}
	if len(pos) < 1 || *file == "" {
		return fail(*jsonOut, 2, "usage: rafter-secrets add <key> --file <path> [--yes]  (value on stdin)")
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	val, err := readValue(*value, os.Stdin)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	res, err := env.engine().Add(pos[0], val, edit.Target{Path: *file}, *yes)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	if *yes {
		env.rescanAfterEdit()
	}
	return reportEdit(env.json, res)
}

// editCmd handles rotate + rm (both operate on all of a secret's targets).
func editCmd(verb string, args []string) int {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	value := fs.String("value", "", "new value (rotate only; else stdin)")
	id := fs.String("id", "", "secret id (disambiguate)")
	yes := fs.Bool("yes", false, "apply (default previews)")
	pos, perr := parseArgs(fs, args)
	if perr != nil {
		return 2
	}
	if len(pos) < 1 && *id == "" {
		return fail(*jsonOut, 2, "usage: rafter-secrets "+verb+" <key> [--yes]")
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	s, err := env.findSecret(arg0(pos), *id)
	if err != nil {
		return fail(*jsonOut, 2, err.Error())
	}
	targets := editTargets(s)
	if len(targets) == 0 {
		return fail(*jsonOut, 2, s.KeyName+" has no editable file locations")
	}
	var res *edit.Result
	if verb == "rotate" {
		val, e := readValue(*value, os.Stdin)
		if e != nil {
			return fail(*jsonOut, 1, e.Error())
		}
		res, err = env.engine().Rotate(s.KeyName, targets, val, "", *yes)
	} else {
		res, err = env.engine().Delete(s.KeyName, targets, "", *yes)
	}
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	if *yes {
		env.rescanAfterEdit()
	}
	return reportEdit(env.json, res)
}

func reportEdit(jsonOut bool, res *edit.Result) int {
	if jsonOut {
		return emit(map[string]any{"ok": true, "op": res.Op, "op_id": res.OpID, "applied": res.Applied, "changes": res.Changes})
	}
	past := map[string]string{"rotate": "Rotated", "add": "Added", "delete": "Deleted"}
	verb := "Would " + res.Op
	if res.Applied {
		verb = past[res.Op]
		if verb == "" {
			verb = "Did " + res.Op
		}
	}
	fmt.Printf("%s %s across %d file(s):\n", verb, res.Key, len(res.Changes))
	for _, c := range res.Changes {
		fmt.Printf("  %s\n", c.Path)
	}
	if !res.Applied {
		fmt.Println("\nPreview only. Re-run with --yes to apply.")
	} else {
		fmt.Printf("\nDone. Undo with: rafter-secrets undo %s\n", res.OpID)
	}
	return 0
}

func cmdUndo(args []string) int {
	fs := flag.NewFlagSet("undo", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	pos, perr := parseArgs(fs, args)
	if perr != nil {
		return 2
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	opID := arg0(pos)
	if opID == "" {
		opID, err = lastOpID(filepath.Dir(env.storePath))
		if err != nil {
			return fail(*jsonOut, 2, "nothing to undo")
		}
	}
	if err := env.engine().Undo(opID); err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	env.rescanAfterEdit()
	if *jsonOut {
		return emit(map[string]any{"ok": true, "undone": opID})
	}
	fmt.Printf("Undid %s.\n", opID)
	return 0
}

func lastOpID(configDir string) (string, error) {
	entries, err := os.ReadDir(filepath.Join(configDir, "backups"))
	if err != nil {
		return "", err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 0 {
		return "", errors.New("no operations")
	}
	sort.Strings(dirs)
	return dirs[len(dirs)-1], nil
}

func cmdHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := loadEnv(*jsonOut)
	if err != nil {
		return fail(*jsonOut, 1, err.Error())
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(env.storePath), "audit.log"))
	if err != nil {
		if *jsonOut {
			return emit(map[string]any{"ok": true, "history": []any{}})
		}
		fmt.Println("No edits yet.")
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if *jsonOut {
		recs := []json.RawMessage{}
		for _, ln := range lines {
			if ln != "" {
				recs = append(recs, json.RawMessage(ln))
			}
		}
		return emit(map[string]any{"ok": true, "history": recs})
	}
	for _, ln := range lines {
		fmt.Println(ln)
	}
	return 0
}
