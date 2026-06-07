# Live key validation — secure-design

The one feature that deliberately sends a real secret value off the machine.
This records the threat model and the boundary before any egress code lands.

## What it is

A **"Test if still live"** button on a key's detail page. On click, Rafter reads
that key's value, makes **one** TLS request to the **issuing vendor's** official
API, and reports a verdict (`valid` / `invalid` / `revoked` / `unknown` /
`unsupported` / `error`). Modeled on betterleaks' `validate` rules
(docs/config.md), but implemented as small hand-written Go validators per vendor
(no embedded CEL engine — see dependencies note).

## Why this doesn't break "values never leave the device"

The principle gets one scoped exception, and the reason it's safe:

> The only party that ever receives the value is **the vendor that issued it —
> who already has it.** Liveness-testing adds no new party to the trust surface.

The value never goes to Rafter (there are no servers), never to an AI agent,
never to a third party. Read → send-to-issuer → forget.

## Boundary / invariants

1. **Opt-in, per-key, per-click.** Never automatic, never on scan, never batched
   without an explicit click. A human action only.
2. **Egress allowlist.** Each validator hardcodes the vendor's official API host.
   The button is shown **only** for a key we've attributed to a vendor we have a
   validator for. No arbitrary/derived URLs ⇒ no SSRF, no mis-send to the wrong
   host.
3. **Read → send → forget.** Value resolved at click time (same path as
   `reveal`/`run`), used for one request, never stored.
4. **No value, no raw body, ever returned.** The endpoint returns only the
   verdict + a small curated, non-sensitive metadata subset (e.g. token scopes).
   The vendor's raw response body is parsed server-side and discarded.
5. **Not in the agent surface.** Consistent with "no values to agents" — this is
   a UI/human action; no agent/MCP/CLI value channel is added.
6. **Kill switch.** `--no-validate` disables the endpoint (403) and hides the
   button — for locked-down / shared installs.
7. **Auth/CSRF.** State-changing `POST /api/secrets/{id}/check-live` rides the
   existing `guard` (loopback Origin / Sec-Fetch-Site) + session cookie.
8. **No retaliation surface.** One request, short timeout, no auto-retry. Verdict
   may be cached briefly by key id (not by value) to avoid double-fire.

## Validators (first set), each a read-only liveness call

| Vendor    | Request                                   | live=200 / dead |
|-----------|-------------------------------------------|-----------------|
| GitHub    | `GET api.github.com/user` (Bearer)        | 200 / 401       |
| OpenAI    | `GET api.openai.com/v1/models` (Bearer)   | 200 / 401       |
| Anthropic | `GET api.anthropic.com/v1/models` (x-api-key) | 200 / 401   |
| Stripe    | `GET api.stripe.com/v1/account` (Basic)   | 200 / 401       |
| Slack     | `POST slack.com/api/auth.test` (Bearer)   | ok:true / ok:false |
| AWS       | STS `GetCallerIdentity` (SigV4)           | 200 / 403       |

Unsupported vendor ⇒ no button (verdict `unsupported`). AWS (SigV4) may be a
fast-follow.

## Consent

The button label/affordance must state plainly that it transmits the key to its
vendor — e.g. *"Test if live — sends this key straight to {Vendor} to check it.
Goes to {Vendor} only, never to Rafter or any AI agent."*

## Dependencies note

We do **not** import betterleaks or a CEL runtime (would pull network/validation
code into a tool whose pitch is "nothing leaves"). We **vendor the detection
ruleset** (data) and **hand-write the validators** from betterleaks' `validate`
rules as the spec. Pin/attribute per docs/design/local-server-auth.md style.
