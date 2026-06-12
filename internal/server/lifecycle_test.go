package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// newTestLifecycle returns a lifecycle with a fast watchdog so the timing
// behaviour can be asserted in milliseconds rather than seconds.
func newTestLifecycle(idle time.Duration) *lifecycle {
	l := newLifecycle(idle)
	l.tick = 5 * time.Millisecond
	l.grace = 20 * time.Millisecond
	return l
}

func waitFor(t *testing.T, cond func() bool, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestLifecycleCloseBeaconExits(t *testing.T) {
	l := newTestLifecycle(time.Hour)
	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.watch(ctx, func() { fired.Add(1) })

	l.beat() // a live client
	l.close()
	waitFor(t, func() bool { return fired.Load() == 1 }, time.Second,
		"close-beacon should shut the server down after the grace window")
}

func TestLifecycleReloadDoesNotExit(t *testing.T) {
	l := newTestLifecycle(time.Hour)
	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.watch(ctx, func() { fired.Add(1) })

	// A reload: close-beacon from the old page, then an immediate heartbeat
	// from the freshly loaded page. The server must stay up.
	l.beat()
	l.close()
	l.beat() // reloaded page re-asserts liveness within the grace window

	time.Sleep(10 * l.grace)
	if fired.Load() != 0 {
		t.Fatal("a reload (close-beacon followed by a heartbeat) must not shut the server down")
	}
}

func TestLifecycleIdleTimeoutDisabled(t *testing.T) {
	l := newTestLifecycle(0) // non-positive → idle-exit disabled
	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.watch(ctx, func() { fired.Add(1) })

	l.beat()
	time.Sleep(20 * l.tick)
	if fired.Load() != 0 {
		t.Fatal("idle timeout of 0 must not exit the server")
	}
}

func TestLifecycleIdleTimeoutExits(t *testing.T) {
	l := newTestLifecycle(15 * time.Millisecond)
	var fired atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.watch(ctx, func() { fired.Add(1) })

	l.beat() // last heartbeat; then go idle
	waitFor(t, func() bool { return fired.Load() == 1 }, time.Second,
		"server should exit after the idle timeout elapses with no heartbeat")
}
