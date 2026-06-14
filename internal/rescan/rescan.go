// Package rescan glues the fsnotify watcher, the scan orchestrator,
// the storage document, and the SSE event bus into a single long-lived
// background loop. It exists as a separate package so internal/watch
// stays focused on raw fs events and doesn't grow a transitive
// dependency on storage or scan.
package rescan

import (
	"context"
	"fmt"
	"sync"

	"github.com/Raftersecurity/rafter-secrets/internal/docstore"
	"github.com/Raftersecurity/rafter-secrets/internal/eventbus"
	"github.com/Raftersecurity/rafter-secrets/internal/scan"
	"github.com/Raftersecurity/rafter-secrets/internal/storage"
	"github.com/Raftersecurity/rafter-secrets/internal/watch"
)

// Config wires the rescanner. Store/Bus are required; Watcher is
// optional — passing nil means "construct one from the doc's
// ScanConfig.Roots".
type Config struct {
	Store   *docstore.Store
	Bus     *eventbus.Bus
	Watcher *watch.Watcher
	// OnError is called for non-fatal scan or save errors. nil = drop.
	OnError func(error)
}

// Rescanner owns the watcher lifecycle. Concurrency safety with the
// HTTP handlers comes from the shared docstore.Store, which Rescan now
// holds only for the brief config-snapshot and apply steps — never for
// the filesystem walk. The mutex below guards the Schedule coalescing
// latch, not the doc.
type Rescanner struct {
	cfg Config

	// mu guards the Schedule latch. running is true while a scan goroutine
	// is in flight; rerun records that at least one more scan was requested
	// while it ran, so a burst of fs events collapses into a single
	// follow-up scan instead of a backlog.
	mu      sync.Mutex
	running bool
	rerun   bool
}

// New validates cfg and returns a Rescanner. If cfg.Watcher is nil, a
// fresh watch.Watcher is created against the doc's ScanConfig.Roots.
// Any partial-setup error from the watcher is returned alongside a
// usable Rescanner so the caller can decide whether to abort or
// proceed.
func New(cfg Config) (*Rescanner, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("rescan: nil store")
	}
	if cfg.Bus == nil {
		return nil, fmt.Errorf("rescan: nil bus")
	}
	var partial error
	if cfg.Watcher == nil {
		var roots []string
		cfg.Store.Read(func(g *storage.Global) {
			roots = append(roots, g.ScanConfig.Roots...)
		})
		w, err := watch.New(roots, 0)
		if err != nil {
			partial = err
		}
		cfg.Watcher = w
	}
	return &Rescanner{cfg: cfg}, partial
}

// Run blocks until ctx is cancelled. Each fs-event burst within the
// watcher's debounce window collapses into one scan via Schedule. Schedule
// returns immediately, honouring the watcher's "onChange MUST NOT block"
// contract — the scan itself runs on a background goroutine.
func (r *Rescanner) Run(ctx context.Context) error {
	if r.cfg.Watcher == nil {
		return fmt.Errorf("rescan: nil watcher")
	}
	defer r.cfg.Watcher.Close()
	return r.cfg.Watcher.Run(ctx, func() {
		r.Schedule(ctx)
	}, r.cfg.OnError)
}

// Schedule requests a rescan without blocking the caller. At most one scan
// runs at a time; requests that arrive while a scan is in flight collapse
// into a single pending rerun, so an edit burst (or a flurry of watcher
// events) produces one follow-up scan rather than a queue of them. It is
// safe to call from the watcher goroutine, the HTTP "rescan now" handler,
// and startup concurrently.
func (r *Rescanner) Schedule(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	r.mu.Lock()
	if r.running {
		// A scan is already in flight; ask it to run once more when it
		// finishes and return immediately.
		r.rerun = true
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()
	go r.drain(ctx)
}

// drain runs scans back-to-back as long as reruns keep being requested,
// then clears the running flag. Exactly one drain goroutine exists at a
// time (guarded by running), so scans never overlap.
func (r *Rescanner) drain(ctx context.Context) {
	for {
		r.Rescan(ctx)
		r.mu.Lock()
		if r.rerun && ctx.Err() == nil {
			r.rerun = false
			r.mu.Unlock()
			continue
		}
		r.running = false
		r.mu.Unlock()
		return
	}
}

// Rescan runs one scan synchronously and publishes per-secret + summary
// events. It is exposed (rather than only-private) so tests and the manual
// --rescan path can drive a single scan deterministically; production
// callers go through Schedule, which serialises and coalesces them.
//
// The filesystem walk runs with NO docstore lock held. Rescan takes the
// lock only twice, both briefly: once to snapshot the scan config, and
// once to fold the observations into the doc and persist. This is the fix
// for rs-1h0: previously the whole walk ran inside Store.Update, so every
// HTTP handler (list/reveal/annotate) blocked for the scan's full duration
// — minutes on a $HOME-wide scope.
func (r *Rescanner) Rescan(ctx context.Context) {
	r.cfg.Bus.Publish(eventbus.Event{Type: eventbus.EventScanStarted})

	// Snapshot the scan scope under a brief read lock, cloning the slices
	// so the lock-free walk can't be tripped by a concurrent config edit.
	var cfg storage.ScanConfig
	r.cfg.Store.Read(func(g *storage.Global) {
		cfg = g.ScanConfig.Clone()
	})

	// The long part: walk the filesystem with the lock released.
	res, err := scan.Observe(ctx, cfg)
	if err != nil {
		if r.cfg.OnError != nil {
			r.cfg.OnError(fmt.Errorf("rescan: scan: %w", err))
		}
		// Always publish a terminal event, even on failure, so the UI's
		// scan-in-progress state ("Looking…") resolves instead of hanging.
		r.cfg.Bus.Publish(eventbus.Event{Type: eventbus.EventScanComplete})
		return
	}

	// The short critical section: fold the observations into the live doc
	// (preserving any annotations a handler made during the walk) and save.
	var changes []scan.Change
	saveErr := r.cfg.Store.Update(func(g *storage.Global) bool {
		changes = res.Apply(g)
		return true
	})
	if saveErr != nil && r.cfg.OnError != nil {
		r.cfg.OnError(fmt.Errorf("rescan: save: %w", saveErr))
	}

	for _, c := range changes {
		r.cfg.Bus.Publish(eventbus.Event{
			Type:     outcomeToEventType(c.Outcome),
			SecretID: c.SecretID,
			KeyName:  c.KeyName,
			Path:     c.Path,
		})
	}

	r.cfg.Bus.Publish(eventbus.Event{
		Type: eventbus.EventScanComplete,
		Stats: &eventbus.ScanStats{
			FilesScanned: res.FilesScanned,
			SecretsFound: res.SecretsFound,
			Errors:       len(res.Errors),
		},
	})
}

func outcomeToEventType(o storage.Outcome) string {
	switch o {
	case storage.OutcomeCreated:
		return eventbus.EventSecretCreated
	case storage.OutcomeDrifted:
		return eventbus.EventSecretDrifted
	default:
		return eventbus.EventSecretRefreshed
	}
}
