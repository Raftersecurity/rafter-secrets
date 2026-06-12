package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Raftersecurity/rafter-secrets/internal/browser"
	"github.com/Raftersecurity/rafter-secrets/internal/docstore"
	"github.com/Raftersecurity/rafter-secrets/internal/edit"
	"github.com/Raftersecurity/rafter-secrets/internal/eventbus"
	rescanpkg "github.com/Raftersecurity/rafter-secrets/internal/rescan"
	"github.com/Raftersecurity/rafter-secrets/internal/scan"
	"github.com/Raftersecurity/rafter-secrets/internal/server"
	"github.com/Raftersecurity/rafter-secrets/internal/storage"
	"github.com/Raftersecurity/rafter-secrets/internal/watch"
	"github.com/Raftersecurity/rafter-secrets/internal/wizard"
)

const defaultIdleTimeout = 30 * time.Minute

// isTTY reports whether f is an interactive terminal (vs a redirected file).
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// writeLaunchURL drops the launch URL (with its single-use token) into an
// owner-only file beside the store, so a headless launch can retrieve it
// without the token landing in a redirected log. Returns the path written.
func writeLaunchURL(storePath, url string) string {
	p := filepath.Join(filepath.Dir(storePath), ".launch-url")
	if err := os.WriteFile(p, []byte(url+"\n"), 0o600); err != nil {
		return "(could not write launch link: " + err.Error() + ")"
	}
	return p
}

func main() {
	// CLI subcommands run and exit before the UI-launch path. A bare
	// invocation (or UI flags like --no-open) falls through to runUI.
	// `serve` is an explicit alias for the default UI launch — drop it and
	// let the flag parser see the rest.
	if len(os.Args) > 1 {
		if os.Args[1] == "serve" {
			os.Args = append(os.Args[:1], os.Args[2:]...)
		} else if code, ok := dispatchCLI(os.Args[1:]); ok {
			os.Exit(code)
		}
	}

	var (
		noOpen      = flag.Bool("no-open", false, "do not auto-open browser")
		noReveal    = flag.Bool("no-reveal", false, "disable revealing secret values (UI + API) — for screen-shares / shared machines")
		idleTimeout = flag.Duration("idle-timeout", defaultIdleTimeout, "exit after this long with no client heartbeat")
		rescan      = flag.Bool("rescan", false, "run a filesystem scan and exit (no UI)")
	)
	flag.Parse()

	// Give the process as many file descriptors as the OS will allow
	// before the watcher starts opening them. macOS defaults the soft
	// limit to 256, which a whole-disk watch blows through almost
	// instantly; raising soft→hard buys the headroom the watcher cap
	// then bounds. Best-effort — a failure here just means we lean
	// harder on the cap.
	if _, err := raiseFileLimit(); err != nil {
		fmt.Fprintf(os.Stderr, "rafter-secrets: could not raise open-file limit (%v); continuing with watch caps\n", err)
	}

	storePath, err := storage.DefaultPath()
	if err != nil {
		log.Fatalf("rafter-secrets: resolve store path: %v", err)
	}
	doc, err := storage.Load(storePath)
	if err != nil {
		log.Fatalf("rafter-secrets: load store: %v", err)
	}

	// First-run setup: if no roots are configured, apply sensible defaults
	// ($HOME + curated excludes) without prompting and go straight to the web
	// app. Onboarding — including adjusting scope — happens in the UI, not at a
	// terminal the target user may never have opened. Persist so later launches
	// skip this.
	if len(doc.ScanConfig.Roots) == 0 {
		if err := wizard.ApplyDefaults(doc); err != nil {
			log.Fatalf("rafter-secrets: first-run setup: %v", err)
		}
		if err := storage.Save(storePath, doc); err != nil {
			log.Fatalf("rafter-secrets: save store: %v", err)
		}
	}

	if *rescan {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		res, err := scan.Run(ctx, doc, doc.ScanConfig)
		if err != nil {
			log.Fatalf("rafter-secrets: scan: %v", err)
		}
		if err := storage.Save(storePath, doc); err != nil {
			log.Fatalf("rafter-secrets: save store: %v", err)
		}
		fmt.Fprintf(os.Stderr,
			"rafter-secrets: scanned %d file(s); %d secret observation(s); %d error(s)\n",
			res.FilesScanned, res.SecretsFound, len(res.Errors))
		return
	}

	store := docstore.New(doc, func(d *storage.Global) error {
		return storage.Save(storePath, d)
	})

	bus := eventbus.New()
	srv, err := server.New(server.Config{
		IdleTimeout:    *idleTimeout,
		RevealDisabled: *noReveal,
		Bus:            bus,
		Store:          store,
		// In-app fixes go through the same edit engine the CLI uses, bound to
		// the CURRENT scan roots (scope can change at runtime via the UI).
		EditEngine: func() *edit.Engine {
			var roots []string
			store.Read(func(g *storage.Global) { roots = append(roots, g.ScanConfig.Roots...) })
			return edit.New(filepath.Dir(storePath), editBoundary(roots))
		},
	})
	if err != nil {
		log.Fatalf("rafter-secrets: %v", err)
	}

	url := srv.URL()
	// The launch URL carries the single-use token. On a real terminal, printing
	// it is fine (your own scrollback). When stderr is redirected (a log file,
	// journal), don't persist the token there — write it to an owner-only file
	// instead and print only the loopback address.
	if isTTY(os.Stderr) {
		fmt.Fprintf(os.Stderr, "rafter-secrets: serving on %s\n", url)
	} else {
		p := writeLaunchURL(storePath, url)
		fmt.Fprintf(os.Stderr, "rafter-secrets: serving on 127.0.0.1 (launch link written to %s)\n", p)
		// Don't leave the launch link (and its spent token) on disk after exit.
		defer func() { _ = os.Remove(p) }()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Translate signals into a graceful Shutdown so Run returns cleanly.
	go func() {
		<-ctx.Done()
		shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shCancel()
		_ = srv.Shutdown(shCtx)
	}()

	// Bring up the fsnotify drift watcher. A partial-setup error
	// (e.g. one root unreadable) is logged but doesn't abort: the
	// other roots are still watched, and the user can fix config
	// without restarting.
	// Exclude the Rafter Secrets store directory itself from the watcher; if a
	// scan root is set to $HOME (the spec default), the store-save
	// landing under ~/.config/rafter-secrets would otherwise re-fire the
	// watcher and loop forever.
	storeDir := filepath.Dir(storePath)
	wch, wchErr := watch.NewWithConfig(watch.Config{
		Roots:       doc.ScanConfig.Roots,
		ExcludeDirs: []string{storeDir},
		// Hand the watcher the SAME excludes the scanner uses so it
		// prunes node_modules/.git/caches/Library instead of opening a
		// file descriptor for every one of them. Without this a $HOME-
		// wide scope exhausts FDs and the UI dies with "too many open
		// files" — the exact failure reported on a whole-disk run.
		Excludes: doc.ScanConfig.Excludes,
	})
	if errors.Is(wchErr, watch.ErrWatchLimit) {
		fmt.Fprintf(os.Stderr, "rafter-secrets: watching a subset of your scan scope (%s); Rafter Secrets will still re-scan periodically and on changes it can see. Narrow your scan roots in settings for full live coverage.\n", wchErr)
	} else if wchErr != nil {
		fmt.Fprintf(os.Stderr, "rafter-secrets: watcher partial setup: %v\n", wchErr)
	}

	rs, rsErr := rescanpkg.New(rescanpkg.Config{
		Store:   store,
		Bus:     bus,
		Watcher: wch,
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "rafter-secrets: %v\n", err)
		},
	})
	if rsErr != nil {
		fmt.Fprintf(os.Stderr, "rafter-secrets: watcher partial setup: %v\n", rsErr)
	}
	if rs != nil {
		go func() {
			if err := rs.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "rafter-secrets: watcher exited: %v\n", err)
			}
		}()
		// Kick off one scan immediately so the UI shows the current
		// inventory on launch instead of an empty list that only fills
		// in when a watched file later changes. Runs in the background
		// so the server is already accepting connections (and the SSE
		// scan_started/scan_complete frames drive the UI's loading
		// state) while a large $HOME is walked.
		go rs.Rescan(ctx)

		// Let the UI's "Scan scope" panel trigger a fresh scan after the
		// user changes which folders to watch. Set before Run (handlers
		// aren't serving yet), so no race. The watcher still covers the
		// original roots until restart; a manual re-scan reflects new scope.
		srv.SetRescan(func() { go rs.Rescan(ctx) })
	}

	if !*noOpen {
		if err := browser.Open(url); err != nil {
			fmt.Fprintf(os.Stderr, "rafter-secrets: could not open browser (%v); paste the URL above instead\n", err)
		}
	}

	// Run blocks until lifecycle watchdog, signal handler, or close-beacon
	// triggers a shutdown.
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("rafter-secrets: server: %v", err)
	}
}
