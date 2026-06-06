# Local server auth — hardening (secure-design)

The web UI runs a localhost HTTP server that can reveal secret values and (now)
edit files. This records the threat model and the three hardening changes.

## What was already solid

Host allowlist (anti-DNS-rebind), Origin check on writes, `SameSite=Strict`
`HttpOnly` session cookie, constant-time token compare, token stripped from the
URL after first exchange. For the target audience (single-user laptop) this is
already good — "other local users" isn't a threat there.

## Residual risks (multi-user / token-leak edges) and the fixes

### #1 — Long-lived bearer token that leaks via argv + stderr
`browser.Open(url)` execs `open/xdg-open/rundll32 <url-with-?token=…>`, putting
the token in **argv** (visible to any local user via `ps`); it's also printed to
stderr (→ persisted if redirected to a log). The token never rotates, so a
captured one grants the **whole session** (reveal all, edit files) for the
server's lifetime, and loopback is reachable by every local user on the host.

**Fix:** split two secrets.
- `launchToken` — in the URL only, **single-use** (atomic compare-and-swap):
  it authorizes exactly one cookie exchange, then it's dead.
- `session` — random, **never in any URL/argv**, carried only in the
  `SameSite=Strict` cookie (and accepted via header for the in-page client).

Result: a `ps`/log-captured launch URL is useless the instant the real browser
exchanges it (sub-second race), and the long-lived credential never appears in
argv or logs. Also: print the token URL to stderr **only when it's a TTY**; when
redirected, print a token-less URL and write the launch URL to a `0600` file in
the config dir for headless retrieval (owner-only, not a world/journal log).

### #2 — Reveal is always on → a session compromise exposes every value
`RevealPolicy` exists in the schema but nothing enforces it.

**Fix:** a `--no-reveal` server flag. When set, `/reveal` returns 403 and the UI
hides "Show value" (`reveal_disabled` in the list response). Shrinks the blast
radius of a session compromise (inventory visible, values not) — for
screen-shares, agent-mediated, or shared-box sessions. Matches the product's
"don't put values where they can leak" stance. (Runtime flag, not persisted; the
4-mode policy field is left as-is.)

### #3 — `guard` fails open when Origin is absent on writes
It rejects only when Origin is present and non-loopback. Not browser-exploitable
(cross-site always sends Origin; SameSite blocks the cookie), but now that writes
mutate files, a non-browser local process with the token could POST without an
Origin.

**Fix:** fail **closed** — require a valid loopback Origin (or
`Sec-Fetch-Site: same-origin`) on every state-changing request. Modern browsers
send Origin on all POST/PUT/DELETE (incl. same-origin), so the real UI is
unaffected; non-browser writes must now also present a same-origin signal.

## Out of scope (noted)

Same-UID-only binding (reject connections from a different OS user) is the real
shared-host fix, but peer-credential checks are clean on a unix socket — which
browsers can't speak — not on loopback TCP. Deferred; #1 is the pragmatic win.
