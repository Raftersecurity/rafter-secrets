package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
)

const (
	cookieName   = "rafter_secrets_session"
	headerName   = "X-Rafter-Secrets-Token"
	queryParam   = "token"
	cookiePath   = "/"
	cookieMaxAge = 0 // session cookie
)

// guard is the outermost middleware. Before any token check it enforces
// two browser-trust-boundary rules that a localhost service handling
// plaintext secrets must not skip:
//
//   - Host allowlist (anti-DNS-rebinding). A malicious page can repoint
//     its own DNS to 127.0.0.1 and make the victim's browser connect to
//     this server, but the browser still sends the attacker's Host
//     header. We refuse any Host that isn't loopback, so rebinding never
//     reaches a real handler even if the token were somehow known.
//   - Origin allowlist on state-changing requests. A cross-site fetch
//     carries the attacker's Origin; we reject any mutating request whose
//     Origin is present and not our own loopback origin. Combined with
//     the SameSite=Strict cookie this closes the CSRF path even if the
//     token leaked into a page the user shouldn't have trusted.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validLoopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if isStateChanging(r.Method) {
			// Fail CLOSED: a state-changing request must carry a same-origin
			// signal — a loopback Origin (modern browsers send it on every
			// POST/PUT/DELETE, incl. same-origin) or Sec-Fetch-Site:same-origin.
			// A request with neither (a non-browser client) is rejected even if
			// it holds the token.
			o := r.Header.Get("Origin")
			if o != "" {
				if !validLoopbackOrigin(o) {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			} else if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
				http.Error(w, "forbidden: cross-site or unverifiable request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isStateChanging reports whether the HTTP method can mutate server
// state. GET/HEAD/OPTIONS are safe; everything else gets the Origin check.
func isStateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// validLoopbackHost reports whether a Host header targets the loopback
// interface. Port is ignored — the connection already arrived on our
// listener, so only the hostname needs vetting.
func validLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port present
	}
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	// Catch other loopback forms (127.0.0.2, etc.) without allowing names.
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// validLoopbackOrigin parses an Origin header and applies the same
// loopback test to its host. A scheme other than http(s) or an
// unparseable value is rejected.
func validLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return validLoopbackHost(u.Host)
}

// requireToken authenticates every request. Credentials arrive via:
//   - ?token=... query string — the SINGLE-USE launch token, valid only for the
//     first cookie exchange (it travels in the launch URL → browser argv, so it
//     must die after one use).
//   - rafter_secrets_session cookie — the long-lived session secret, set after a
//     successful launch exchange. Never appears in any URL.
//   - X-Rafter-Secrets-Token header — the session secret, for the in-page client.
//
// On the launch exchange we burn the launch token (atomic CAS), set the session
// cookie, and strip the token from the URL.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authedByCookie(r) || s.authedByHeader(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.authedByQuery(r) {
			// Single-use: only the first exchange with the launch token wins.
			if !s.launchUsed.CompareAndSwap(false, true) {
				http.Error(w, "this launch link was already used — restart rafter-secrets for a fresh one", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    s.token,
				Path:     cookiePath,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   cookieMaxAge,
			})
			// Redirect to a token-less URL so the launch token doesn't linger in
			// browser history or the referer header.
			redirectURL := *r.URL
			q := redirectURL.Query()
			q.Del(queryParam)
			redirectURL.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURL.RequestURI(), http.StatusSeeOther)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *Server) authedByQuery(r *http.Request) bool {
	got := r.URL.Query().Get(queryParam)
	return got != "" && constTimeEq(got, s.launchToken)
}

func (s *Server) authedByHeader(r *http.Request) bool {
	got := r.Header.Get(headerName)
	return got != "" && constTimeEq(got, s.token)
}

func (s *Server) authedByCookie(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return constTimeEq(c.Value, s.token)
}

func constTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
