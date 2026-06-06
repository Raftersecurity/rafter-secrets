package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Raftersecurity/rafter-secrets/internal/docstore"
	"github.com/Raftersecurity/rafter-secrets/internal/edit"
	"github.com/Raftersecurity/rafter-secrets/internal/eventbus"
)

type Config struct {
	// IdleTimeout: exit after this long with no client heartbeat.
	IdleTimeout time.Duration

	// Bus, if non-nil, is the source for the /api/events SSE stream.
	// The route is registered unconditionally; with no bus configured
	// it returns 503 so a misconfigured launch fails loudly instead of
	// silently dropping drift updates on the floor.
	Bus *eventbus.Bus

	// Store, if non-nil, is the doc the secrets API reads and mutates.
	// /api/secrets and friends return 503 when nil; this matches Bus's
	// "fail loud" pattern for misconfigured launches.
	Store *docstore.Store

	// EditEngine, if non-nil, returns an edit.Engine bound to the CURRENT
	// scan roots (scope can change at runtime, so it's a factory). The in-app
	// fix endpoints (secure/undo) use it; nil makes them return 503.
	EditEngine func() *edit.Engine

	// RevealDisabled turns off the /reveal endpoint (403) and hides "Show
	// value" in the UI — the --no-reveal mode. Shrinks the blast radius of a
	// session compromise for screen-shares / agent / shared-box sessions.
	RevealDisabled bool
}

// SetRescan installs the callback the scan-config endpoint fires after the
// user changes scan scope in the UI. It's set after New (the rescanner is
// built later in startup) but before Run, so there's no race with handlers.
func (s *Server) SetRescan(fn func()) { s.rescan = fn }

type Server struct {
	httpSrv  *http.Server
	listener net.Listener
	// launchToken authorizes exactly ONE cookie exchange (it travels in the
	// launch URL → browser argv → ps, so it must be single-use). token is the
	// long-lived session credential the cookie/header carry; it never appears
	// in a URL.
	launchToken    string
	launchUsed     atomic.Bool
	token          string
	url            string
	life           *lifecycle
	bus            *eventbus.Bus
	store          *docstore.Store
	rescan         func()
	editEngine     func() *edit.Engine
	revealDisabled bool
}

// New binds to a random port on 127.0.0.1 and prepares (but does not start)
// the HTTP server. Call Run to serve.
func New(cfg Config) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind localhost: %w", err)
	}

	launch, err := randomToken(32)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("launch token: %w", err)
	}
	session, err := randomToken(32)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("session secret: %w", err)
	}

	s := &Server{
		listener:       ln,
		launchToken:    launch,
		token:          session,
		life:           newLifecycle(cfg.IdleTimeout),
		bus:            cfg.Bus,
		store:          cfg.Store,
		editEngine:     cfg.EditEngine,
		revealDisabled: cfg.RevealDisabled,
	}
	addr := ln.Addr().(*net.TCPAddr)
	s.url = fmt.Sprintf("http://127.0.0.1:%d/?token=%s", addr.Port, launch)

	mux := http.NewServeMux()
	s.routes(mux)

	s.httpSrv = &http.Server{
		// guard (Host/Origin trust-boundary checks) wraps requireToken
		// (session-token auth) wraps the routes. Host vetting runs before
		// the token check so a DNS-rebinding probe never reaches auth.
		Handler:           s.guard(s.requireToken(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) URL() string { return s.url }

// Run serves HTTP until ctx is cancelled or the lifecycle watchdog fires.
func (s *Server) Run(ctx context.Context) error {
	go s.life.watch(ctx, func() {
		// Idle timeout: trigger graceful shutdown.
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shCtx)
	})

	// Mark heartbeat now so the idle watchdog has a starting point.
	s.life.beat()

	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
