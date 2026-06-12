package server

import (
	"context"
	"sync/atomic"
	"time"
)

// closeGrace is how long a close-beacon must stand, with no newer heartbeat,
// before the server exits. A page *reload* fires the close-beacon and then
// immediately re-heartbeats from the fresh page; this window lets that
// reconnect land so a refresh doesn't kill the server out from under the user.
const closeGrace = 4 * time.Second

// lifecycle tracks client liveness so the binary can exit when the browser
// tab is closed (close-beacon) or the user wanders off (heartbeat stale).
type lifecycle struct {
	idleTimeout time.Duration
	lastBeatNS  atomic.Int64 // unix nanos of last heartbeat
	closedAtNS  atomic.Int64 // unix nanos a close-beacon arrived; 0 = none pending

	// tick + grace are the watchdog cadence and the close-beacon grace window.
	// Fields (not consts) so tests can shrink them; production uses the
	// defaults set in newLifecycle.
	tick  time.Duration
	grace time.Duration
}

func newLifecycle(idle time.Duration) *lifecycle {
	return &lifecycle{idleTimeout: idle, tick: time.Second, grace: closeGrace}
}

func (l *lifecycle) beat() {
	// A live heartbeat cancels any pending close-beacon: a reloaded page sends
	// one straight away, which means the "tab closed" signal was really a
	// refresh and the server must stay up.
	l.closedAtNS.Store(0)
	l.lastBeatNS.Store(time.Now().UnixNano())
}

func (l *lifecycle) close() {
	l.closedAtNS.Store(time.Now().UnixNano())
}

// watch runs until ctx is cancelled or a shutdown trigger fires, at which
// point it invokes onShutdown exactly once.
func (l *lifecycle) watch(ctx context.Context, onShutdown func()) {
	tick := time.NewTicker(l.tick)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Close-beacon: honour it only if no heartbeat has arrived since it
			// fired (else it was a reload) and the grace window has elapsed.
			if c := l.closedAtNS.Load(); c != 0 {
				if l.lastBeatNS.Load() < c && time.Since(time.Unix(0, c)) > l.grace {
					onShutdown()
					return
				}
			}
			// A non-positive idle timeout disables idle-exit entirely (the
			// close-beacon path above still applies). Without this guard,
			// idleTimeout==0 makes every elapsed interval "stale" and the
			// server exits on the first tick.
			if l.idleTimeout <= 0 {
				continue
			}
			last := time.Unix(0, l.lastBeatNS.Load())
			if time.Since(last) > l.idleTimeout {
				onShutdown()
				return
			}
		}
	}
}
