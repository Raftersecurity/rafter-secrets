// Rafter Secrets — inventory UI for people who have never opened a terminal.
// Read-and-annotate only: it shows what's on the machine and lets you tag/note
// it. Any change to a file is a deliberate CLI action, never a click here.
//
// Server API (read + annotate only):
//   GET  /api/secrets · POST /api/secrets (manual entry) ·
//   POST /api/secrets/{id}/reveal · PUT /api/secrets/{id}/annotation ·
//   POST /api/secrets/{id}/{stale,rotated} · GET /api/events (SSE)

(function () {
  "use strict";

  const content = document.getElementById("content");
  const drawerRoot = document.getElementById("drawer-root");
  const modalRoot = document.getElementById("modal-root");
  const walkthroughRoot = document.getElementById("walkthrough-root");
  const toastWrap = document.getElementById("toast-wrap");
  const scanStatus = document.getElementById("scan-status");
  const scanStatusText = document.getElementById("scan-status-text");

  let state = { secrets: [], scan_home: null };
  let selectedId = null;
  let view = localStorage.getItem("rafter.view") || "folder";
  let tourChecked = false;
  let collapsedGroups = (() => { try { return new Set(JSON.parse(localStorage.getItem("rafter.collapsed") || "[]")); } catch (_) { return new Set(); } })();
  function persistCollapsed() { try { localStorage.setItem("rafter.collapsed", JSON.stringify(Array.from(collapsedGroups))); } catch (_) {} }
  const revealed = new Map();
  const revealing = new Set(); // ids whose value is being read from disk right now
  let saveTimer = null, saveState = "idle";

  // ---- helpers ---------------------------------------------------------
  function el(tag, attrs, kids) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") e.className = attrs[k];
      else if (k === "html") e.innerHTML = attrs[k];
      else if (k === "text") e.textContent = attrs[k];
      else if (k.startsWith("on") && typeof attrs[k] === "function") e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    }
    if (kids) for (const c of [].concat(kids)) if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    return e;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function setToast(text, isErr) {
    if (!text) return;
    const t = el("div", { class: "toast " + (isErr ? "err" : "ok") }, [
      el("span", { class: "ti", html: isErr ? ICON.warn : ICON.check }),
      document.createTextNode(text),
    ]);
    toastWrap.appendChild(t);
    setTimeout(() => { t.style.transition = "opacity .3s"; t.style.opacity = "0"; setTimeout(() => t.remove(), 300); }, 3200);
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
    if (!res.ok) {
      let msg = res.statusText;
      try { const b = await res.json(); if (b && b.error) msg = b.error; } catch (_) {}
      const err = new Error(msg || "request failed"); err.status = res.status; throw err;
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    return ct.startsWith("application/json") ? res.json() : res.text();
  }

  // ---- vendor / risk model (unchanged logic) --------------------------
  const VENDORS = [
    [/stripe|sk_live|sk_test|rk_live/i, "Stripe", "St"],
    [/(anthropic|claude|sk-ant)/i, "Anthropic", "An"],
    [/(openai|sk-proj|sk-[A-Za-z0-9]{20})/i, "OpenAI", "Ai"],
    [/(github|gh_|ghp_|gho_)/i, "GitHub", "Gh"],
    [/(aws|akia|secret_access_key|aws_access)/i, "AWS", "Aw"],
    [/(google|gcp|gcloud|firebase)/i, "Google", "Go"],
    [/sendgrid|sg\./i, "SendGrid", "Sg"],
    [/twilio/i, "Twilio", "Tw"],
    [/slack|xox[baprs]/i, "Slack", "Sl"],
    [/(postgres|psql|database_url|db_url|mysql|mongo)/i, "Database", "Db"],
    [/jwt|signing/i, "Signing key", "Jw"],
    [/resend/i, "Resend", "Re"],
    [/vercel/i, "Vercel", "Ve"],
    [/supabase/i, "Supabase", "Sb"],
    [/(npm|registry)/i, "npm", "Np"],
    [/docker/i, "Docker", "Dk"],
    [/(secret|token|key|password|passwd|pat|api)/i, "Credential", "Key"],
  ];
  function vendorFor(k) { k = k || ""; for (const [re, n, c] of VENDORS) if (re.test(k)) return { name: n, chip: c }; return { name: "Saved value", chip: (k.slice(0, 2) || "··").toUpperCase() }; }
  // The recognised vendor (Stripe, OpenAI…), or null for the generic fallbacks —
  // so we show the real variable name instead of a vague "Credential".
  function vendorLabel(k) { const n = vendorFor(k).name; return (n === "Credential" || n === "Saved value") ? null : n; }

  function parsePerm(p) { if (!p) return null; const m = /(\d{3,4})$/.exec(p); if (!m) return null; const o = m[1].slice(-3); return { group: (parseInt(o[1], 8) & 4) !== 0, other: (parseInt(o[2], 8) & 4) !== 0 }; }
  function isManual(s) { return typeof s.id === "string" && s.id.indexOf("manual:") === 0; }
  function fileLocations(s) { return (s.found_in || []).filter((f) => f.path && f.source_type !== "manual"); }
  function exposure(s) { let w = null; for (const f of fileLocations(s)) { const pm = parsePerm(f.permissions); if (!pm) continue; if (pm.other) return { level: "other", path: f.path }; if (pm.group && !w) w = { level: "group", path: f.path }; } return w; }
  function isDuplicated(s) { return fileLocations(s).length > 1; }
  function isStale(s) { return !!(s.annotation && s.annotation.stale); }
  function projectsOf(s) { return (s.annotation && s.annotation.tags) || []; }
  // A template/example env file (.env.example, .env.sample, …) is committed on
  // purpose, so its git signals aren't leaks — don't warn on them. (Mirrors the
  // classifier, which already demotes these out of Secrets.)
  function isExampleFile(s) { return fileLocations(s).some((f) => /example|sample|template|\.dist|\.tmpl|\.tpl/.test(((f.path || "").split("/").pop() || "").toLowerCase())); }
  function inGitHistory(s) { return !isExampleFile(s) && fileLocations(s).some((f) => f.appears_in_git_history === true); }
  // In a repo, not committed, and explicitly not ignored → one `git add` from
  // being committed and pushed. (in_gitignore === false means we checked; nil
  // is omitted and means unknown.)
  function notGitignored(s) { return !isExampleFile(s) && fileLocations(s).some((f) => f.in_git_repo === true && f.appears_in_git_history !== true && f.in_gitignore === false); }
  function gitIgnoredOk(s) { return !inGitHistory(s) && fileLocations(s).some((f) => f.in_gitignore === true); }
  // Note: file permissions ("exposed") deliberately do NOT flag a secret as
  // "worth a look" — chmod only stops other accounts, which is marginal. The
  // one permissions surface left is the calm Lock-down banner + the per-secret
  // button. Real risk = leak vectors (git) + lifecycle.
  // Duplication is a note, not a risk — it no longer pulls an item into "Worth a
  // look" (it shows as informational in the drawer instead).
  function hasWarnings(s) { return !isStale(s) && (inGitHistory(s) || notGitignored(s) || isExpiringSoon(s)); }
  function needsAttention(s) { return hasWarnings(s) && !isIgnored(s); }

  // ---- ignored warnings (UI-local) -------------------------------------
  // "Ignore" is a per-secret acknowledgement: it drops the secret out of
  // "Worth a look" and softens its pill, but never hides the underlying
  // finding (the drawer still spells it out). Kept in localStorage like
  // the view/theme prefs — it's a local, single-user app, so this is a
  // display preference, not a change to the inventory the CLI reads.
  // Keyed by secret id (a fingerprint, not a value); a rotated secret gets
  // a new id, so its warnings correctly resurface.
  let ignoredSet = loadIgnored();
  function loadIgnored() { try { return new Set(JSON.parse(localStorage.getItem("rafter.ignored") || "[]")); } catch (_) { return new Set(); } }
  function persistIgnored() { try { localStorage.setItem("rafter.ignored", JSON.stringify(Array.from(ignoredSet))); } catch (_) {} }
  function isIgnored(s) { return ignoredSet.has(s.id); }
  function setIgnored(s, on) { if (on) ignoredSet.add(s.id); else ignoredSet.delete(s.id); persistIgnored(); render(); if (selectedId) renderDrawer(); }

  // ---- Secrets / Environment lens --------------------------------------
  // The classifier tags each entry secret|env. Secrets is the hero view
  // (exposure, lock-down, rotation); Environment is the calm full list of
  // ordinary config (PORT, NODE_ENV, …) so real secrets aren't buried.
  let lens = localStorage.getItem("rafter.lens") || "secrets";
  let showAllEnv = false; // Environment "show all variables" escape hatch
  let focus = null; // null | "committed" | "dup" — figure-driven focus filter
  let searchQ = ""; // search filter
  function matchesSearch(s) {
    if (!searchQ) return true;
    const hay = (s.key_name + " " + vendorFor(s.key_name).name + " " + projectsOf(s).join(" ") + " " + fileLocations(s).map((f) => f.path || "").join(" ")).toLowerCase();
    return hay.indexOf(searchQ) >= 0;
  }
  // Effective kind: a user override wins, else the classifier, else "secret"
  // (old records / fail-safe default).
  function effectiveKind(s) { return (s.annotation && s.annotation.override_kind) || s.kind || "secret"; }
  function isEnv(s) { return effectiveKind(s) === "env"; }
  // The two lenses are a disjoint partition (each item in exactly one). The
  // Environment side has an escape hatch to show ALL variables, so a user can
  // double-check the classifier didn't mis-sort one.
  function lensSecrets() { if (lens === "env" && showAllEnv) return state.secrets.slice(); return state.secrets.filter((s) => lens === "env" ? isEnv(s) : !isEnv(s)); }
  // annotationBody builds the FULL annotation. The server does a full replace,
  // so every writer must send all fields or it would wipe the others.
  function annotationBody(s, over) {
    const a = s.annotation || {};
    return Object.assign({ source_url: a.source_url || "", owner: a.owner || "", notes: a.notes || "", rotate_url: a.rotate_url || "", tags: projectsOf(s), override_kind: a.override_kind || "", expires_at: a.expires_at || "", scope: a.scope || "" }, over || {});
  }
  // ---- expiry (optional, proactive) ------------------------------------
  function expiryDate(s) { const v = s.annotation && s.annotation.expires_at; if (!v) return null; const d = new Date(v + "T00:00:00"); return isNaN(d.getTime()) ? null : d; }
  function daysUntilExpiry(s) { const d = expiryDate(s); if (!d) return null; return Math.ceil((d.getTime() - Date.now()) / 86400000); }
  function isExpiringSoon(s) { if (isStale(s)) return false; const n = daysUntilExpiry(s); return n !== null && n <= 30; }
  async function setOverrideKind(s, kind) {
    const a = s.annotation || {};
    try {
      await api(`/api/secrets/${encodeURIComponent(s.id)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(annotationBody(s, { override_kind: kind })) });
      s.annotation = Object.assign({}, a, { override_kind: kind });
      setToast(kind === "env" ? "Moved to Environment." : kind === "secret" ? "Moved to Secrets." : "Reset to auto.");
      render(); if (selectedId) renderDrawer();
    } catch (e) { setToast("Couldn't update: " + e.message, true); }
  }

  // ---- project suggestions ("which repo does this live in?") -----------
  // The scanner doesn't tag a git root, so we infer the project from the
  // path: a *project-local* dotenv (.env / .env.* / .envrc) sits at the
  // root of a repo, and that repo's folder name is almost always the
  // GitHub repo name. Home-level config dirs (~/.aws, ~/.config, …) and
  // the home root itself are skipped — those aren't project-scoped.
  function repoNameFromPath(path) {
    if (!path) return null;
    const i = path.lastIndexOf("/");
    if (i < 0) return null;
    const base = path.slice(i + 1);
    if (!/^\.env(\.|rc$|$)/.test(base)) return null;       // project-local dotenv only
    const dir = path.slice(0, i);
    const seg = dir.slice(dir.lastIndexOf("/") + 1);
    if (!seg || seg[0] === ".") return null;               // skip ~/.config-style dirs
    if (state.scan_home && dir === state.scan_home) return null; // skip the home root
    return seg;
  }
  // Repo names this particular secret lives in.
  function repoNamesFor(s) { const out = []; for (const f of fileLocations(s)) { const n = repoNameFromPath(f.path); if (n && out.indexOf(n) < 0) out.push(n); } return out; }
  // Every project name we could offer: ones already used to tag a secret,
  // plus every repo folder we can infer from a dotenv path across the scan.
  function knownProjects() {
    const out = [], seen = new Set();
    const push = (n) => { if (!n) return; const k = n.toLowerCase(); if (seen.has(k)) return; seen.add(k); out.push(n); };
    for (const o of state.secrets) projectsOf(o).forEach(push);
    for (const o of state.secrets) repoNamesFor(o).forEach(push);
    return out;
  }
  // Ranked suggestions for one secret: its own repo(s) first (flagged as
  // repo-derived for the icon), then other known projects — minus any it
  // already carries.
  function projectSuggestions(s) {
    const have = new Set(projectsOf(s).map((p) => p.toLowerCase()));
    const out = [], seen = new Set();
    const push = (name, fromRepo) => { if (!name) return; const k = name.toLowerCase(); if (have.has(k) || seen.has(k)) return; seen.add(k); out.push({ name, fromRepo }); };
    repoNamesFor(s).forEach((n) => push(n, true));
    const ownRepos = new Set(repoNamesFor(s).map((n) => n.toLowerCase()));
    knownProjects().forEach((n) => push(n, ownRepos.has(n.toLowerCase())));
    return out.slice(0, 6);
  }

  // ---- data ------------------------------------------------------------
  async function loadSecrets() {
    try {
      const body = await api("/api/secrets");
      state.secrets = body.secrets || [];
      state.revealDisabled = !!body.reveal_disabled;
      const roots = (body.scan_config && body.scan_config.roots) || [];
      state.scan_home = roots.slice().sort((a, b) => a.length - b.length)[0] || null;
      render();
      if (!tourChecked) { tourChecked = true; if (state.secrets.length && localStorage.getItem("rafter.tour") !== "done") startWalkthrough(); }
    } catch (e) {
      clear(content);
      content.appendChild(el("div", { class: "empty" }, [ el("div", { class: "ec", html: ICON.warn }), el("h3", { text: "Couldn't reach Rafter Secrets" }), el("p", { text: e.message + ". Try reloading." }) ]));
    }
  }

  // ---- render ----------------------------------------------------------
  function render() {
    clear(content);
    if (state.secrets.length === 0) { content.appendChild(renderEmpty()); content.appendChild(renderFoot()); return; }

    content.appendChild(renderLensToggle());
    const pool = lensSecrets().filter(matchesSearch);

    if (lens === "env") {
      content.appendChild(renderEnvHeader(pool.length));
      const allN = state.secrets.length, envN = state.secrets.filter(isEnv).length;
      content.appendChild(el("div", { class: "envtoggle" }, [
        el("button", { class: "btn ghost sm" + (showAllEnv ? " active" : ""), onclick: () => { showAllEnv = !showAllEnv; render(); }, text: showAllEnv ? "Showing all " + allN + " variables — back to config only (" + envN + ")" : "Show all " + allN + " variables (incl. secrets) — double-check the sort" }),
      ]));
      // Same grouping as Secrets — by folder / project / flat.
      if (view === "folder") content.appendChild(renderFolder(pool));
      else if (view === "project") renderProjects(pool).forEach((n) => content.appendChild(n));
      else content.appendChild(renderList(pool.slice().sort(byName), false));
      content.appendChild(renderFoot());
      if (selectedId && !state.secrets.some((s) => s.id === selectedId)) closeDrawer();
      return;
    }

    // Figure-driven focus (clicked a stat card): just those + a bulk prompt.
    if (focus) {
      content.appendChild(renderFocusView(focus, pool));
      content.appendChild(renderFoot());
      if (selectedId && !state.secrets.some((s) => s.id === selectedId)) closeDrawer();
      return;
    }

    content.appendChild(renderHero(pool)); // the lock-all action now lives in the hero
    content.appendChild(renderFigures(pool));

    const attn = pool.filter(needsAttention);
    if (view === "folder") {
      content.appendChild(renderFolder(pool));
    } else if (view === "project") {
      renderProjects(pool).forEach((n) => content.appendChild(n));
    } else {
      if (attn.length) {
        content.appendChild(section("Worth a look", attn.length, "we'd tidy these first"));
        content.appendChild(renderList(attn, true));
      }
      const rest = pool.filter((s) => !needsAttention(s)).sort(byName);
      content.appendChild(section(attn.length ? "Everything else" : "Your secrets", rest.length, null));
      content.appendChild(renderList(rest, false));
    }
    content.appendChild(renderFoot());
    if (selectedId && !state.secrets.some((s) => s.id === selectedId)) closeDrawer();
  }
  function renderLensToggle() {
    const nSec = state.secrets.filter((s) => !isEnv(s)).length;
    const nEnv = state.secrets.filter(isEnv).length;
    const seg = el("div", { class: "lens" });
    const mk = (key, label, n) => {
      const b = el("button", { class: "lensbtn" + (lens === key ? " active" : "") }, [ document.createTextNode(label), el("span", { class: "lenscount", text: String(n) }) ]);
      b.addEventListener("click", () => { if (lens === key) return; lens = key; localStorage.setItem("rafter.lens", lens); render(); });
      return b;
    };
    seg.appendChild(mk("secrets", "Secrets", nSec));
    seg.appendChild(mk("env", "Environment", nEnv));
    return seg;
  }
  function renderEnvHeader(n) {
    return el("div", { class: "hero" }, [
      el("div", { class: "eyebrow", text: "On this computer" }),
      el("h1", { class: "statement" }, [ el("span", { class: "num", text: String(n) }), document.createTextNode(" environment value" + (n === 1 ? "" : "s") + " — ordinary config, not secrets.") ]),
      el("p", { class: "lede", html: "Ports, hostnames, log levels, feature flags — the non-sensitive settings in your <code>.env</code> and shell files. Nothing here is flagged. Spot one that's actually a secret? Open it and tap <b>“This is a secret.”</b>" }),
    ]);
  }
  function byName(a, b) { return vendorFor(a.key_name).name.localeCompare(vendorFor(b.key_name).name); }

  function renderHero(pool) {
    const live = (pool || state.secrets).filter((s) => !isStale(s));
    const total = live.length;
    const attn = live.filter(needsAttention).length;
    const exposedSecrets = live.filter((s) => exposure(s));
    const exposedN = exposedSecrets.length;

    // The risk count is the one big number; everything else is smaller context.
    const big = el("div", { class: "herobig " + (attn > 0 ? "risk" : "calm") });
    if (attn > 0) {
      big.appendChild(el("div", { class: "bignum", text: String(attn) }));
      big.appendChild(el("div", { class: "herotext" }, [
        el("h1", { class: "bigh", text: (attn === 1 ? "secret worth a look" : "secrets worth a look") }),
        el("div", { class: "bigsub", text: "of " + total + " you're tracking — the rest look fine." }),
      ]));
    } else {
      big.appendChild(el("div", { class: "bignum ok", text: String(total) }));
      big.appendChild(el("div", { class: "herotext" }, [
        el("h1", { class: "bigh", text: (total === 1 ? "secret, all tidy" : "secrets, all tidy") }),
        el("div", { class: "bigsub", text: "nothing committed to git, nothing flagged." }),
      ]));
    }

    const hero = el("div", { class: "hero" }, [ el("div", { class: "eyebrow", text: "On this computer" }), big ]);
    // One primary action, attached to the hero (not a floating card).
    if (exposedN > 0) {
      hero.appendChild(el("div", { class: "heroact" }, [
        el("button", { class: "btn primary", onclick: () => secureAllFix(exposedSecrets), text: "Lock down " + exposedN + " readable file" + (exposedN === 1 ? "" : "s") }),
        el("span", { class: "hint", text: "make them private to you — previewed first, undoable" }),
      ]));
    }
    hero.appendChild(el("p", { class: "lede", html: "Passwords, keys, and tokens sitting in plain files — readable by anything you run, <b>including AI coding agents</b>. Nothing here is changed, moved, or uploaded." }));
    return hero;
  }

  // Value-free bulk prompts for the focus views.
  function committedBulkPrompt(list) {
    const lines = list.map((s) => "- " + s.key_name + vendorPhrase(s) + " — in " + whereLine(s)).join("\n");
    return "These secrets are committed to a git repository (they may already be pushed). For EACH one, walk me through rotating it with the provider (revoke the old key, create a new one), updating the file, and removing the old value from git history — in a safe order, with exact commands. Don't ask me to paste any secret value.\n\n" + lines;
  }
  function dupBulkPrompt(list) {
    const lines = list.map((s) => "- " + s.key_name + vendorPhrase(s) + " — in " + fileLocations(s).map((f) => prettyPath(f.path)).join(", ")).join("\n");
    return "These secrets are duplicated across several files. Help me pick the canonical copy and consolidate (or confirm each copy is intentional), so rotating one key doesn't mean editing many files. Don't ask me to paste any secret value.\n\n" + lines;
  }
  // renderFocusView is the filtered view for a clicked stat card.
  const FOCUS = {
    committed: { match: inGitHistory, risk: true, eyebrow: "Committed to git", h: (n) => "secret" + (n === 1 ? "" : "s") + " committed to git", sub: "in history — possibly already pushed. Rotate each and purge it.", btn: (n) => "Copy one prompt to fix all " + n, prompt: committedBulkPrompt, none: "None committed to git — nice." },
    dup: { match: isDuplicated, risk: false, eyebrow: "Saved in 2+ places", h: (n) => "secret" + (n === 1 ? "" : "s") + " in more than one file", sub: "the same secret copied across files — replace it everywhere, or whatever still uses the old copy breaks.", btn: (n) => "Copy a prompt to consolidate " + n, prompt: dupBulkPrompt, none: "No duplicates — nice." },
  };
  function renderFocusView(kind, pool) {
    const cfg = FOCUS[kind];
    const list = pool.filter(cfg.match);
    const box = el("div");
    box.appendChild(el("div", { class: "hero" }, [
      el("div", { class: "eyebrow", text: cfg.eyebrow }),
      el("div", { class: "herobig " + (cfg.risk ? "risk" : "calm") }, [
        el("div", { class: "bignum" + (cfg.risk ? "" : " ok"), text: String(list.length) }),
        el("div", { class: "herotext" }, [ el("h1", { class: "bigh", text: cfg.h(list.length) }), el("div", { class: "bigsub", text: cfg.sub }) ]),
      ]),
      el("div", { class: "heroact" }, [
        list.length ? agentBtn(cfg.btn(list.length), cfg.prompt(list)) : null,
        el("button", { class: "btn ghost sm", onclick: () => { focus = null; render(); }, text: "← back to all secrets" }),
      ]),
    ]));
    if (list.length) box.appendChild(renderList(list.slice().sort(byName), cfg.risk));
    else box.appendChild(el("p", { class: "lede", text: cfg.none }));
    return box;
  }

  function renderFigures(pool) {
    const live = (pool || state.secrets).filter((s) => !isStale(s));
    const total = live.length;
    const committed = live.filter(inGitHistory).length;
    const dup = live.filter(isDuplicated).length;
    const pct = (n) => total ? Math.max(4, Math.round((n / total) * 100)) : 0;
    const wrap = el("div", { class: "figures" });
    // A stat card with a count becomes a one-click filter to those items.
    const filterFig = (fig, n, kind, color) => {
      if (n <= 0) return fig;
      fig.classList.add("clickable");
      fig.title = "Show only these";
      fig.addEventListener("click", () => { focus = kind; render(); });
      fig.appendChild(el("div", { class: "figlink", text: "Filter to these →", style: "color:" + color }));
      return fig;
    };
    wrap.appendChild(figure("Tracked", total, null, "ink", 100, "saved in plain files"));
    wrap.appendChild(filterFig(figure("Committed to git", committed, committed ? ["bad", "Leak"] : ["ok", "Clear"], "red", pct(committed), committed ? "may be pushed somewhere" : "none in history"), committed, "committed", "var(--red)"));
    wrap.appendChild(filterFig(figure("In 2+ places", dup, dup ? ["warn", "Action"] : ["ok", "Good"], "amber", pct(dup), dup ? "the same secret in several files" : "no duplicates"), dup, "dup", "var(--amber)"));
    return wrap;
  }
  function figure(label, n, badge, barColor, barPct, sub) {
    const top = el("div", { class: "ftop" }, [ el("span", { class: "flbl", text: label }) ]);
    if (badge) top.appendChild(el("span", { class: "fbadge " + badge[0], text: badge[1] }));
    return el("div", { class: "figure" }, [
      top,
      el("div", { class: "fnum", text: String(n) }),
      el("div", { class: "fbar" }, [ el("i", { class: barColor, style: "width:" + barPct + "%" }) ]),
      el("div", { class: "fsub", text: sub }),
    ]);
  }

  function section(title, count, hint) {
    return el("div", { class: "sec" }, [
      el("h2", { text: title }),
      count != null ? el("span", { class: "sc", text: count }) : null,
      hint ? el("span", { class: "shint", text: hint }) : null,
    ]);
  }

  // ---- rows ------------------------------------------------------------
  function renderList(secrets, flagged) {
    const list = el("div", { class: "list" });
    for (const s of secrets) list.appendChild(renderRow(s, flagged));
    return list;
  }
  function renderRow(s, flagged) {
    const v = vendorFor(s.key_name);
    let cls = "row";
    if (flagged) cls += (inGitHistory(s) || (isExpiringSoon(s) && daysUntilExpiry(s) < 0)) ? " flag danger" : " flag warn";
    if (isStale(s)) cls += " stale";
    const row = el("div", { class: cls });
    row.appendChild(el("div", { class: "tile", text: v.chip }));

    // Title is the variable name itself (OPENAI_API_KEY) — what the user
    // recognises. Subtext is the vendor (if known) then where it lives.
    const vl = vendorLabel(s.key_name);
    const subKids = [];
    if (vl) { subKids.push(el("span", { text: vl }), el("span", { class: "sdot" })); }
    subKids.push(el("span", { text: contextLabel(s) }));
    const sub = el("div", { class: "rsub" }, subKids);
    row.appendChild(el("div", { class: "rbody" }, [ el("code", { class: "rname", text: s.key_name }), sub ]));

    // Status pill is the main right-side element; the masked-dots glyph is gone
    // (the pill already says what it is) and Ignore moved into the drawer.
    const rright = el("div", { class: "rright" });
    rright.appendChild(statusPill(s));
    rright.appendChild(el("span", { class: "chev", html: ICON.chev }));
    row.appendChild(rright);
    row.addEventListener("click", () => openDrawer(s.id));
    return row;
  }

  function contextLabel(s) {
    const p = projectsOf(s)[0];
    if (p) return "In your " + p + " project";
    if (isManual(s)) return "Added by you";
    const f = (s.found_in || [])[0] || {};
    switch (f.source_type) {
      case "shell-rc": return "In your shell startup";
      case "keystore": return "In your system keyring";
      default: break;
    }
    const base = f.path ? splitPath(f.path).base : "";
    if (base === "credentials") return "In your AWS sign-in";
    if (base === "config.json") return "In your Docker login";
    if (base === "hosts.yml") return "In your GitHub CLI";
    if (base === "settings.json") return "In your Claude settings";
    if (base === ".npmrc") return "In your npm config";
    if (base) return "In " + base;
    return "On your computer";
  }

  function statusPill(s) {
    if (lens === "env") return pill("muted", "Config");
    if (isStale(s)) return pill("muted", "Not in use");
    if (isIgnored(s) && hasWarnings(s)) return pill("muted", "Warning ignored");
    if (inGitHistory(s)) return pill("danger", "Committed to git");
    if (notGitignored(s)) return pill("warn", "Not git-ignored");
    if (isDuplicated(s)) return pill("muted", "Saved in " + fileLocations(s).length + " places");
    if (isExpiringSoon(s)) { const n = daysUntilExpiry(s); return pill(n < 0 ? "danger" : "warn", n < 0 ? "Expired" : n === 0 ? "Expires today" : "Expires in " + n + "d"); }
    if (isManual(s)) return pill("manual", "You're tracking this");
    return pill("muted", "Tracked");
  }
  function pill(cls, text) { return el("span", { class: "pill " + cls }, [ cls === "manual" ? null : el("span", { class: "pd" }), document.createTextNode(text) ]); }

  // ---- folder + project views -----------------------------------------
  // collapsibleGroup is a big, clickable group header (greater hierarchy than
  // the rows) with its rows below; collapse state persists per group key.
  function collapsibleGroup(label, count, rowsNode, key) {
    const collapsed = collapsedGroups.has(key);
    const head = el("div", { class: "grouphead" + (collapsed ? " collapsed" : "") }, [
      el("span", { class: "gchev", html: ICON.chev }),
      el("span", { class: "gtitle", text: label }),
      count != null ? el("span", { class: "gcount", text: count }) : null,
    ]);
    head.addEventListener("click", () => { if (collapsedGroups.has(key)) collapsedGroups.delete(key); else collapsedGroups.add(key); persistCollapsed(); render(); });
    const wrap = el("div", { class: "groupwrap" });
    if (!collapsed) wrap.appendChild(rowsNode);
    return el("div", { class: "group" }, [ head, wrap ]);
  }
  function renderFolder(secrets) {
    const byDir = new Map();
    for (const s of secrets) { const f = fileLocations(s)[0]; const d = f ? prettyPath(dirOf(f.path)) : "(added by hand)"; if (!byDir.has(d)) byDir.set(d, []); byDir.get(d).push(s); }
    const box = el("div");
    for (const d of Array.from(byDir.keys()).sort()) {
      box.appendChild(collapsibleGroup(d + "/", byDir.get(d).length, renderList(byDir.get(d).sort(byName), false), "folder:" + d));
    }
    return box;
  }
  function renderProjects(secrets) {
    const groups = new Map(); const untagged = [];
    for (const s of secrets) { const ps = projectsOf(s); if (!ps.length) { untagged.push(s); continue; } for (const p of ps) { if (!groups.has(p)) groups.set(p, []); groups.get(p).push(s); } }
    const out = [];
    out.push(el("div", { class: "viewnote", html: "Grouped by <b>project</b>. Open any secret to tag it — we suggest the repo it lives in, so bucketing is usually one click." }));
    for (const name of Array.from(groups.keys()).sort()) { out.push(collapsibleGroup(name, groups.get(name).length, renderList(groups.get(name).sort(byName), false), "project:" + name)); }
    if (untagged.length) { out.push(collapsibleGroup("No project yet", untagged.length, renderList(untagged.sort(byName), false), "project:__untagged__")); }
    return out;
  }

  function renderEmpty() {
    return el("div", { class: "empty" }, [
      el("div", { class: "ec", html: ICON.check }),
      el("h3", { text: "Nothing saved in the open." }),
      el("p", { text: "Rafter Secrets didn't find any passwords or keys in plain files. It keeps watching as files change." }),
    ]);
  }
  function renderFoot() {
    return el("div", { class: "foot" }, [ el("span", { class: "sh", html: ICON.shield }), el("span", { text: "Nothing ever leaves this computer. Rafter only looks — until you ask it to fix something, and every change is shown first and can be undone." }) ]);
  }

  // ---- reveal ----------------------------------------------------------
  async function toggleReveal(s) {
    if (revealed.has(s.id)) { revealed.delete(s.id); renderDrawer(); return; }
    revealing.add(s.id); renderDrawer(); // show "Reading…" — disk read can lag on big inventories
    try { const b = await api(`/api/secrets/${encodeURIComponent(s.id)}/reveal`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); revealed.set(s.id, b.value); }
    catch (e) { if (e.status === 422) setToast("No live value to show for this one.", true); else if (e.status === 410) setToast("That value just changed — refreshing.", true); else setToast("Couldn't read it: " + e.message, true); }
    finally { revealing.delete(s.id); renderDrawer(); }
  }

  // ---- in-app fixes (preview → confirm → apply → undo) -----------------
  // The fix is a button, never a terminal command. Every write is previewed
  // server-side (apply:false), confirmed by the user, applied (apply:true),
  // and offered back as an Undo. Goes through the same edit engine the CLI
  // uses — backup, atomic write, verify, audit, undo.
  async function secureFix(s) {
    let prev;
    try { prev = await api(`/api/secrets/${encodeURIComponent(s.id)}/secure`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ apply: false }) }); }
    catch (e) { setToast("Couldn't check that fix: " + e.message, true); return; }
    const files = (prev && prev.files) || [];
    if (!files.length) { setToast("Already locked down — only you can read it."); return; }
    confirmFix({
      title: "Lock down " + s.key_name + "?",
      lead: "Only you will be able to read " + (files.length > 1 ? "these files" : "this file") + ". The secret itself doesn’t change, and you can undo it.",
      detail: files.map((f) => splitPath(f.path).base + "   " + f.old_mode + " → " + f.new_mode),
      confirmText: "Lock it down",
      onConfirm: async () => {
        try {
          const r = await api(`/api/secrets/${encodeURIComponent(s.id)}/secure`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ apply: true }) });
          closeModal();
          toastWithUndo("Locked down — only you can read it now.", r.op_id);
          await loadSecrets(); renderDrawer();
        } catch (e) { setToast("Couldn't apply that: " + e.message, true); }
      },
    });
  }
  function confirmFix(o) {
    const modal = el("div", { class: "modal confirm" }, [
      el("div", { class: "mhead" }, [ el("h2", { text: o.title }), el("button", { class: "btn ghost sm mclose", onclick: closeModal, text: "✕" }) ]),
      el("p", { class: "msub", text: o.lead }),
      (o.detail && o.detail.length) ? el("div", { class: "confirm-detail mono" }, o.detail.map((d) => el("div", { text: d }))) : null,
      el("div", { class: "mactions" }, [
        el("button", { class: "btn sm", onclick: closeModal, text: "Cancel" }),
        el("button", { class: "btn primary sm", onclick: o.onConfirm, text: o.confirmText }),
      ]),
    ]);
    clear(modalRoot);
    modalRoot.appendChild(el("div", { class: "modal-wrap", onclick: (e) => { if (e.target.classList.contains("modal-wrap")) closeModal(); } }, [ modal ]));
  }
  function toastWithUndo(text, opId) {
    const t = el("div", { class: "toast ok" }, [ el("span", { class: "ti", html: ICON.check }), document.createTextNode(text) ]);
    if (opId) t.appendChild(el("button", { class: "toast-undo", text: "Undo", onclick: async () => {
      t.remove();
      try { await api("/api/undo", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ op_id: opId }) }); setToast("Undone."); await loadSecrets(); renderDrawer(); }
      catch (e) { setToast("Couldn't undo: " + e.message, true); }
    } }));
    toastWrap.appendChild(t);
    setTimeout(() => { t.style.transition = "opacity .3s"; t.style.opacity = "0"; setTimeout(() => t.remove(), 300); }, 9000);
  }

  async function secureAllFix(targets) {
    // Scope to the passed secrets (the filtered/searched exposed set) so the
    // hero button locks down exactly what's on screen — not every exposed file.
    const ids = (targets && targets.length) ? targets.map((s) => s.id) : null;
    const body = (apply) => JSON.stringify(ids ? { apply, ids } : { apply });
    let prev;
    try { prev = await api("/api/secure-all", { method: "POST", headers: { "Content-Type": "application/json" }, body: body(false) }); }
    catch (e) { setToast("Couldn't check that fix: " + e.message, true); return; }
    const files = (prev && prev.files) || [];
    const skipped = (prev && prev.skipped_not_owned) || [];
    if (!files.length) { setToast(skipped.length ? "Nothing here can be locked down automatically." : "Everything's already private to you."); return; }
    let lead = "Only you will be able to read " + (files.length > 1 ? "these files" : "this file") + ". The secrets themselves don’t change, and you can undo it.";
    if (skipped.length) lead += " (" + skipped.length + " owned by another user can’t be changed here.)";
    confirmFix({
      title: "Lock down " + files.length + " file" + (files.length > 1 ? "s" : "") + "?",
      lead,
      detail: files.map((f) => splitPath(f.path).base + "   " + f.old_mode + " → " + f.new_mode),
      confirmText: "Lock them down",
      onConfirm: async () => {
        try {
          const r = await api("/api/secure-all", { method: "POST", headers: { "Content-Type": "application/json" }, body: body(true) });
          closeModal();
          const n = (r.files || []).length;
          toastWithUndo(n + " file" + (n === 1 ? "" : "s") + " locked down — only you can read " + (n === 1 ? "it" : "them") + " now.", r.op_id);
          await loadSecrets(); renderDrawer();
        } catch (e) { setToast("Couldn't apply that: " + e.message, true); }
      },
    });
  }
  function rotateFix(s) {
    const input = el("input", { class: "scope-input", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "paste the new value from the provider" });
    const modal = el("div", { class: "modal confirm" }, [
      el("div", { class: "mhead" }, [ el("h2", { text: "Replace " + s.key_name }), el("button", { class: "btn ghost sm mclose", onclick: closeModal, text: "✕" }) ]),
      el("p", { class: "msub", html: "Make a new value at the provider, then paste it here — Rafter swaps it into your file" + (fileLocations(s).length > 1 ? "s" : "") + ". It <b>doesn’t</b> turn off the old one at the provider; do that on their site once this works." }),
      el("div", { class: "scope-add" }, [ input ]),
      el("div", { class: "mactions" }, [ el("button", { class: "btn sm", onclick: closeModal, text: "Cancel" }), el("button", { class: "btn primary sm", text: "Replace it", onclick: () => doRotate(s, input.value) }) ]),
    ]);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); doRotate(s, input.value); } });
    clear(modalRoot);
    modalRoot.appendChild(el("div", { class: "modal-wrap", onclick: (e) => { if (e.target.classList.contains("modal-wrap")) closeModal(); } }, [ modal ]));
    input.focus();
  }
  async function doRotate(s, value) {
    value = (value || "").trim();
    if (!value) { setToast("Paste the new value first.", true); return; }
    let prev;
    try { prev = await api(`/api/secrets/${encodeURIComponent(s.id)}/rotate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value, apply: false }) }); }
    catch (e) { setToast("Couldn't prepare that: " + e.message, true); return; }
    const files = (prev && prev.files) || [];
    if (!files.length) { setToast("Nothing to update for this one.", true); return; }
    confirmFix({
      title: "Replace " + s.key_name + " in " + files.length + " file" + (files.length > 1 ? "s" : "") + "?",
      lead: "Your file" + (files.length > 1 ? "s get" : " gets") + " the new value (the old one is backed up — you can undo). This does not revoke the old key at the provider.",
      detail: files.map((p) => splitPath(p).base),
      confirmText: "Replace it",
      onConfirm: async () => {
        try {
          const r = await api(`/api/secrets/${encodeURIComponent(s.id)}/rotate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value, apply: true }) });
          closeModal();
          const n = (r.files || []).length;
          toastWithUndo("Replaced in " + n + " file" + (n === 1 ? "" : "s") + ". Now turn off the old key at the provider.", r.op_id);
          await loadSecrets(); renderDrawer();
        } catch (e) { setToast("Couldn't replace it: " + e.message, true); }
      },
    });
  }
  function renderLockAllBanner(n) {
    return el("div", { class: "lockall" }, [
      el("span", { class: "ci", html: ICON.shield }),
      el("div", { class: "lockall-txt" }, [
        el("div", { class: "lockall-h", text: n + " secret" + (n > 1 ? "s are" : " is") + " readable by other accounts on this computer" }),
        el("div", { class: "lockall-s", text: "Make them private to you — previewed first, and undoable." }),
      ]),
      el("button", { class: "btn primary", onclick: secureAllFix, text: "Lock them all down" }),
    ]);
  }

  // ---- first-run walkthrough -------------------------------------------
  // The comprehension layer: three must-see screens (what's here · what's a
  // secret · make them private — which actually fixes something) then optional
  // learn-more. Auto-runs on first launch, re-launchable from the "?" button.
  function startWalkthrough() {
    let i = 0;
    const lock = { checked: false, files: 0, done: false, n: 0 };
    const screens = [welcome, whatIs, makePrivate, allSet];
    function close(done) { if (done) { try { localStorage.setItem("rafter.tour", "done"); } catch (_) {} } clear(walkthroughRoot); }
    function go(n) { i = n; draw(); }
    function next() { i < screens.length - 1 ? go(i + 1) : close(true); }
    function draw() { screens[i](); }
    // Mount the (animated) scrim ONCE; screen changes only swap the body, so the
    // scrim-in fade doesn't replay on every Next → no flash.
    const skip = el("button", { class: "wt-skip", onclick: () => close(true), text: "Skip tour" });
    const body = el("div", { class: "wt" });
    clear(walkthroughRoot);
    walkthroughRoot.appendChild(el("div", { class: "wt-scrim" }, [skip, body]));
    function setBody(kids) { clear(body); for (const k of kids) if (k != null) body.appendChild(k); }
    function frame(kids, buttons) {
      skip.textContent = "Skip tour";
      const dots = el("div", { class: "wt-dots" });
      for (let k = 0; k < screens.length; k++) dots.appendChild(el("div", { class: "wt-dot" + (k === i ? " on" : "") }));
      const actions = el("div", { class: "wt-actions" }, [dots].concat(buttons || [el("button", { class: "btn primary", onclick: next, text: "Next →" })]));
      setBody(kids.concat([actions]));
    }
    function welcome() {
      frame([
        el("div", { class: "wt-eyebrow", text: "Welcome" }),
        el("h1", { text: "Rafter Secrets helps you manage the secrets on your device." }),
        el("p", { text: "We scan your computer for anything that looks like a secret, so you can see what’s there and tidy up what’s risky." }),
        el("p", { html: "<b>Your secrets never leave this device.</b> Nothing is uploaded — ever." }),
        el("p", { text: "We’ll look through your home folder — you can change which folders anytime from the gear menu." }),
      ], [el("button", { class: "btn primary", onclick: next, text: "Looks good →" })]);
    }
    function whatIs() {
      frame([
        el("div", { class: "wt-eyebrow", text: "1 · The basics" }),
        el("h1", { text: "What’s a secret?" }),
        el("p", { text: "A secret is a key or password that proves who you are to a computer system." }),
        el("ul", {}, [
          el("li", { html: "<span>🔑</span><span>A <b>password</b> lets a person log into an account.</span>" }),
          el("li", { html: "<span>🤖</span><span>An <b>API key</b> lets one app talk to another — no human involved.</span>" }),
          el("li", { html: "<span>🗄️</span><span>Other keys — like a <b>database password</b> — can be used by people or machines.</span>" }),
        ]),
        el("p", { text: "They look like this:" }),
        el("div", { class: "demos" }, [el("span", { class: "demo", text: "sk_live_••••••••" }), el("span", { class: "demo", text: "AKIA••••••••" }), el("span", { class: "demo", text: "postgres://••••" })]),
      ]);
    }
    function makePrivate() {
      const box = lock.done
        ? el("div", { class: "wt-lockbox" }, [el("span", { class: "wt-done" }, [el("span", { class: "ci", html: ICON.check }), document.createTextNode(" " + lock.n + (lock.n === 1 ? " file is" : " files are") + " now private to you.")])])
        : el("div", { class: "wt-lockbox" }, [el("span", { html: lock.checked ? (lock.files ? "<b>" + lock.files + "</b> of your secret files can be opened by other accounts on this computer right now." : "Good news — your secret files are already private to you.") : "Checking your files…" })]);
      let buttons;
      if (lock.done || (lock.checked && lock.files === 0)) buttons = [el("button", { class: "btn primary", onclick: next, text: "Next →" })];
      else { const lb = el("button", { class: "btn primary", onclick: doLock, text: "Lock them down" }); if (!lock.checked) lb.disabled = true; buttons = [lb, el("button", { class: "btn", onclick: next, text: "Skip for now" })]; }
      frame([
        el("div", { class: "wt-eyebrow", text: "2 · Make them private" }),
        el("h1", { text: "Make sure only you can open them." }),
        el("p", { html: "Some of your secret files can be opened by <b>other accounts on this computer</b> — not just you. We can make them private to your account. This changes who can open the file, never the secret itself — and you can undo it." }),
        box,
      ], buttons);
      if (!lock.checked && !lock.done) {
        api("/api/secure-all", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ apply: false }) })
          .then((prev) => { lock.checked = true; lock.files = (prev && prev.files || []).length; draw(); })
          .catch(() => { lock.checked = true; lock.files = 0; draw(); });
      }
    }
    function doLock() {
      api("/api/secure-all", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ apply: true }) })
        .then(async (r) => { lock.done = true; lock.n = (r && r.files || []).length; await loadSecrets(); draw(); })
        .catch((e) => setToast("Couldn't lock them down: " + e.message, true));
    }
    function allSet() {
      frame([
        el("div", { class: "wt-eyebrow", text: "You’re all set" }),
        el("h1", { text: "That’s the gist." }),
        el("p", { text: "Here’s everything we found on your device — grouped, searchable, and calm. Open any secret to tag it, note where it came from, or replace it." }),
      ], [el("button", { class: "btn primary", onclick: () => close(true), text: "Go to my dashboard" }), el("button", { class: "btn", onclick: learnMore, text: "Learn a bit more" })]);
    }
    function learnMore() {
      skip.textContent = "Done";
      setBody([
        el("div", { class: "wt-eyebrow", text: "Good to know" }),
        el("h1", { text: "Two things worth understanding." }),
        el("div", { class: "wt-card" }, [el("h3", { text: "Revoke vs. delete" }), el("p", { html: "When you’re done with a key, <b>revoke</b> it at the site you got it from (Stripe, AWS, …). Deleting your copy isn’t enough — if someone else already grabbed it, they can still use it until you revoke. Rafter shows you the key and links you there; you do the revoking on their site." })]),
        el("div", { class: "wt-card" }, [el("h3", { text: "Rotating a key" }), el("p", { text: "Rotating just means turning off the old key and switching to a new one. If you ever think your device was compromised, rotate — it’s the safe reset." })]),
        el("div", { class: "wt-actions" }, [el("div", { class: "wt-dots" }), el("button", { class: "btn primary", onclick: () => close(true), text: "Go to my dashboard" })]),
      ]);
    }
    draw();
  }

  // ---- drawer ----------------------------------------------------------
  function openDrawer(id) { selectedId = id; renderDrawer(); }
  function closeDrawer() { selectedId = null; clear(drawerRoot); }
  function renderDrawer() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) { closeDrawer(); return; }
    const v = vendorFor(s.key_name);
    // Mount the animated scrim + drawer shell once; later renders swap only the
    // body so drawer-in/scrim-in don't replay (no flash). Scroll is preserved.
    let drawerEl = drawerRoot.querySelector(".drawer");
    if (!drawerEl) {
      clear(drawerRoot);
      drawerRoot.appendChild(el("div", { class: "scrim", onclick: closeDrawer }));
      drawerEl = el("div", { class: "drawer" });
      drawerRoot.appendChild(drawerEl);
    }
    const prevScroll = (drawerEl.querySelector(".dscroll") || {}).scrollTop || 0;
    const body = el("div", { class: "dscroll" });

    body.appendChild(el("div", { class: "dhead" }, [
      el("div", { class: "tile", text: v.chip }),
      el("div", { class: "dtitles" }, [ el("h2", { text: s.key_name }), el("div", { class: "dtype" }, vendorLabel(s.key_name) ? [ el("span", { class: "em", text: vendorLabel(s.key_name) }), document.createTextNode(" · " + contextLabel(s).toLowerCase()) ] : [ document.createTextNode(contextLabel(s).toLowerCase()) ]) ]),
      el("button", { class: "btn ghost sm mclose", onclick: closeDrawer, text: "✕" }),
    ]));

    // One recommended next action, right under the title. The full set still
    // lives in the finding cards + "Replacing this key" below.
    const primary = primaryAction(s);
    if (primary) body.appendChild(primary);

    if (!isManual(s)) {
      const env = isEnv(s);
      body.appendChild(el("div", { class: "kindbar" }, [
        el("span", { class: "kindlabel", text: env ? "Classified as environment / config" : "Classified as a secret" }),
        el("button", { class: "btn ghost sm", text: env ? "This is a secret →" : "This isn’t a secret →", onclick: () => setOverrideKind(s, env ? "secret" : "env") }),
      ]));
    }

    const isRev = revealed.has(s.id);
    if (isManual(s)) body.appendChild(el("div", { class: "valuebox" }, [ el("span", { class: "v hidden", text: "added by you — no file value" }) ]));
    else if (state.revealDisabled) body.appendChild(el("div", { class: "valuebox" }, [
      el("span", { class: "v hidden", text: "••••••••••••" }),
      el("span", { class: "hint", text: "showing values is turned off (--no-reveal)" }),
    ]));
    else if (revealing.has(s.id)) body.appendChild(el("div", { class: "valuebox" }, [
      el("span", { class: "v hidden", text: "••••••••••••" }),
      el("button", { class: "btn sm", disabled: "disabled" }, [ el("span", { class: "spin" }), document.createTextNode("Reading…") ]),
    ]));
    else body.appendChild(el("div", { class: "valuebox" }, [
      el("span", { class: "v " + (isRev ? "revealed" : "hidden"), text: isRev ? revealed.get(s.id) : "••••••••••••" }),
      isRev ? el("button", { class: "btn sm", onclick: () => copy(revealed.get(s.id), "Copied"), text: "Copy" }) : null,
      el("button", { class: "btn sm", onclick: () => toggleReveal(s), text: isRev ? "Hide" : "Show value" }),
    ]));

    const findings = buildFindings(s);
    body.appendChild(el("div", { class: "blk-h", text: "What this means" }));
    if (!findings.length) body.appendChild(el("div", { class: "finding ok" }, [ el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.check }), document.createTextNode(isManual(s) ? "Tracked by you." : "Looks fine.") ]), el("p", { class: "fb", text: isManual(s) ? "You added this by hand. Keep a note of where it lives below." : "Stored in a file only you can read, and only found in one place." }) ]));
    else {
      const ign = isIgnored(s);
      if (ign) body.appendChild(el("div", { class: "ignbanner" }, [
        el("span", { class: "ii", html: ICON.muted }),
        document.createTextNode("You’re ignoring " + (findings.length > 1 ? "these — they’re" : "this — it’s") + " hidden from “Worth a look”. "),
        el("a", { href: "#", onclick: (e) => { e.preventDefault(); setIgnored(s, false); }, text: "Show it again" }),
      ]));
      findings.forEach((f) => body.appendChild(f));
      if (!ign) body.appendChild(el("div", { class: "ignore-act" }, [
        el("button", { class: "btn ghost sm", onclick: () => setIgnored(s, true), text: "Ignore " + (findings.length > 1 ? "these warnings" : "this warning") }),
        el("span", { class: "ignhint", text: "moves it out of “Worth a look”" }),
      ]));
    }

    body.appendChild(el("div", { class: "blk-h", text: "Projects" }));
    body.appendChild(renderProjectEditor(s));

    if (!isManual(s) || (s.found_in || []).length) { body.appendChild(el("div", { class: "blk-h", text: "Where it's stored" })); body.appendChild(renderLocations(s)); }

    body.appendChild(el("div", { class: "blk-h", text: "Notes" }));
    body.appendChild(renderNotes(s));

    if (!isManual(s) && fileLocations(s).length) {
      body.appendChild(el("div", { class: "blk-h", text: "Replacing this key" }));
      body.appendChild(el("div", { class: "fact" }, [
        el("button", { class: "btn primary sm", onclick: () => rotateFix(s), text: "Replace the value" }),
        el("span", { class: "hint", text: "updates your file(s) · previewed · undoable" }),
      ]));
      // Hand off to the user's agent — covers any provider, including ones we
      // can't test or rotate ourselves. Prompts never contain the value.
      body.appendChild(el("div", { class: "fact agentrow" }, [
        agentBtn("Rotate it — prompt for your agent", PROMPT.rotate(s)),
        agentBtn("Is it still live? — prompt for your agent", PROMPT.testLive(s)),
      ]));
    }

    clear(drawerEl);
    drawerEl.appendChild(body);
    body.scrollTop = prevScroll;
  }

  // ---- agent hand-off prompts -----------------------------------------
  // Copy a context-rich, VALUE-FREE prompt the user pastes into their AI agent
  // for step-by-step help. Includes the key name, vendor, file and problem —
  // never the secret value. This is how we cover *arbitrary* keys: the agent
  // has the provider knowledge we can't hard-code.
  function whereLine(s) { const f = fileLocations(s)[0]; return f && f.path ? prettyPath(f.path) : "(a saved value, no file)"; }
  function vendorPhrase(s) { const v = vendorLabel(s.key_name); return v ? " (a " + v + " key)" : ""; }
  function agentBtn(label, prompt) { return el("button", { class: "btn ghost sm agentcopy", title: "Copy a prompt to paste into your AI coding agent — no secret value is included", onclick: (e) => { e.stopPropagation(); copy(prompt, "Prompt copied — paste it into your agent"); } }, [ el("span", { class: "fi", html: ICON.copy }), document.createTextNode(label) ]); }
  function agentFact(label, prompt) { return el("div", { class: "fact" }, [ agentBtn(label, prompt) ]); }
  const PROMPT = {
    rotate: (s) => `My secret ${s.key_name}${vendorPhrase(s)} lives in ${whereLine(s)}. Walk me through rotating it safely, step by step: where to revoke or roll the key with the provider, how to create a replacement, how to update the file, and how to confirm the old one is dead. Give exact commands for my OS. Don't ask me to paste the secret value.`,
    gitCommitted: (s) => `The secret ${s.key_name}${vendorPhrase(s)} is committed to a git repository (file: ${whereLine(s)}). Help me, step by step: (1) rotate it with the provider — revoke the old key and create a new one; (2) update the file; (3) remove the old value from git history, and explain the force-push and blast-radius implications. Exact commands. Don't ask me to paste the value.`,
    gitignore: (s) => `The file ${whereLine(s)} holds the secret ${s.key_name} and is inside a git repo but isn't git-ignored. Show me how to add it to .gitignore and verify it isn't already tracked. Exact commands.`,
    lockdown: (s) => `The file ${whereLine(s)} (holds the secret ${s.key_name}) is readable by other accounts on this computer. Show me how to restrict it to my user only, and explain what that does and doesn't protect against. Exact commands for my OS.`,
    testLive: (s) => `How can I check whether the API key ${s.key_name}${vendorPhrase(s)} is still active? Give me a safe, read-only way to test it against the provider, and if it's live, how to rotate it. The key is in ${whereLine(s)}. I'll run it myself — don't ask me to paste the value here.`,
  };

  // primaryAction is the single most-important next step for a secret, surfaced
  // right under the drawer title. Order = worst first.
  function primaryAction(s) {
    if (isManual(s) || !fileLocations(s).length) return null;
    if (inGitHistory(s)) return el("div", { class: "primact" }, [ el("button", { class: "btn primary sm", onclick: () => rotateFix(s), text: "Replace the value" }), agentBtn("Rotate it — prompt for your agent", PROMPT.rotate(s)) ]);
    if (exposure(s)) return el("div", { class: "primact" }, [ el("button", { class: "btn primary sm", onclick: () => secureFix(s), text: "Lock it down" }), el("span", { class: "hint", text: "make it private to you · undoable" }) ]);
    if (notGitignored(s)) return el("div", { class: "primact" }, [ agentBtn("Add it to .gitignore — prompt for your agent", PROMPT.gitignore(s)) ]);
    return null;
  }

  function buildFindings(s) {
    const out = [];
    if (inGitHistory(s)) {
      out.push(el("div", { class: "finding danger" }, [
        el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.warn }), document.createTextNode("This secret is committed to git") ]),
        el("p", { class: "fb", html: "It’s tracked in a git repo, so it may already be in your history — and pushed somewhere public. Locking the file down won’t help once it’s in git: <b>rotate this key</b>, then remove the value from the file." }),
        agentFact("Copy prompt for your agent", PROMPT.gitCommitted(s)),
      ]));
    }
    if (notGitignored(s)) {
      out.push(el("div", { class: "finding warn" }, [
        el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.warn }), document.createTextNode("Not in .gitignore") ]),
        el("p", { class: "fb", html: "This file is inside a git repo but <b>isn’t git-ignored</b> — one <code>git add</code> away from being committed and pushed. Add it to <code>.gitignore</code> so it can’t be." }),
        agentFact("Copy prompt for your agent", PROMPT.gitignore(s)),
      ]));
    } else if (gitIgnoredOk(s)) {
      out.push(el("div", { class: "finding ok" }, [
        el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.check }), document.createTextNode("Ignored by git") ]),
        el("p", { class: "fb", html: "This file is in <code>.gitignore</code>, so it won’t be committed or pushed — the right place to keep a local secret." }),
      ]));
    }
    const ex = exposure(s);
    if (ex) {
      // Calm, compact — just the secret-specific CTA. (Permissions is marginal;
      // the verbose explanation was cut.)
      out.push(el("div", { class: "finding" }, [
        el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.lock }), document.createTextNode("Readable by other accounts on this computer") ]),
        el("div", { class: "fact", style: "margin-top:11px" }, [ el("button", { class: "btn primary sm", onclick: () => secureFix(s), text: "Lock it down" }), agentBtn("Or ask your agent", PROMPT.lockdown(s)) ]),
      ]));
    }
    if (isDuplicated(s)) out.push(el("div", { class: "finding" }, [ el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.copy }), document.createTextNode("Saved in " + fileLocations(s).length + " files") ]), el("p", { class: "fb", text: "Just so you know — if you ever replace it, update every copy or the apps still on the old one break. See them all under “Where it’s stored”." }) ]));
    if (isExpiringSoon(s)) { const n = daysUntilExpiry(s); out.push(el("div", { class: "finding " + (n < 0 ? "danger" : "warn") }, [ el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.warn }), document.createTextNode(n < 0 ? "This key has expired" : "This key expires soon") ]), el("p", { class: "fb", text: n < 0 ? "It expired " + (-n) + " day" + (n === -1 ? "" : "s") + " ago — replace it and update where it's used." : "Expires in " + n + " day" + (n === 1 ? "" : "s") + ". Plan to replace it before then." }), agentFact("Copy prompt for your agent", PROMPT.rotate(s)) ])); }
    return out;
  }

  // Per-file git status, so when a key is in several files the user can see
  // WHICH one is the committed leak.
  function locGitTag(f) {
    if (f.appears_in_git_history === true) return el("span", { class: "loctag danger" }, [ el("span", { class: "fi", html: ICON.warn }), document.createTextNode("committed to git") ]);
    if (f.in_git_repo === true && f.in_gitignore === false) return el("span", { class: "loctag warn", text: "not git-ignored" });
    if (f.in_gitignore === true) return el("span", { class: "loctag ok", text: "git-ignored" });
    return null;
  }
  function renderLocations(s) {
    const ul = el("ul", { class: "locs" });
    for (const f of s.found_in || []) {
      if (!f.path && !f.keystore) continue;
      let ls = null;
      if (f.source_type === "manual") ls = el("div", { class: "ls", text: "you noted this" });
      else if (f.keystore) ls = el("div", { class: "ls", text: "system keyring · viewing here is coming soon" });
      else { const t = locGitTag(f); if (t) ls = el("div", { class: "ls" }, [ t ]); } // which file is the committed one
      const li = el("li", {}, [
        el("span", { class: "li-ico", html: f.keystore ? ICON.lock : ICON.file }),
        el("div", { style: "min-width:0" }, [ el("div", { class: "lp", text: f.path ? prettyPath(f.path) : keystoreName(f.keystore) }), ls ]),
      ]);
      // Open the file in the user's default editor — the simple alternative to
      // the (cut) "how to replace this key" walkthrough.
      if (f.path && f.source_type !== "manual") li.appendChild(el("button", { class: "btn ghost sm li-open", title: "Open this file in your editor", onclick: () => openFile(f.path), text: "Open" }));
      ul.appendChild(li);
    }
    return ul;
  }
  async function openFile(path) {
    try { await api("/api/open", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path }) }); setToast("Opening " + splitPath(path).base + " in your editor…"); }
    catch (e) { setToast("Couldn't open it: " + e.message, true); }
  }
  function keystoreName(k) { return /keychain/i.test(k) ? "macOS Keychain" : "System keyring"; }

  function renderProjectEditor(s) {
    const box = el("div");
    const wrap = el("div", { class: "chips" });
    const ps = projectsOf(s);
    for (const p of ps) wrap.appendChild(el("span", { class: "tag" }, [ document.createTextNode(p), el("span", { class: "x", title: "Remove", html: ICON.x, onclick: () => setProjects(s, ps.filter((x) => x !== p)) }) ]));
    const add = el("span", { class: "tag add", text: "+ project" });
    add.addEventListener("click", () => {
      const input = el("input", { class: "chip-input", type: "text", placeholder: "project name" });
      wrap.replaceChild(input, add); input.focus();
      const commit = () => { const val = input.value.trim(); if (val && ps.indexOf(val) < 0) setProjects(s, ps.concat([val])); else renderDrawer(); };
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") commit(); if (e.key === "Escape") renderDrawer(); });
      input.addEventListener("blur", commit);
    });
    wrap.appendChild(add);
    box.appendChild(wrap);

    // One-click suggestions, repo-derived names first (with a repo icon).
    const sugg = projectSuggestions(s);
    if (sugg.length) {
      const row = el("div", { class: "suggests" }, [ el("span", { class: "slabel", text: "Suggested" }) ]);
      for (const g of sugg) {
        const chip = el("span", { class: "tag suggest", title: g.fromRepo ? "From the repo this secret lives in" : "Used on your other secrets" }, [
          g.fromRepo ? el("span", { class: "gh", html: ICON.repo }) : null,
          document.createTextNode(g.name),
        ]);
        chip.addEventListener("click", () => setProjects(s, projectsOf(s).concat([g.name])));
        row.appendChild(chip);
      }
      box.appendChild(row);
    }
    return box;
  }
  async function setProjects(s, projects) {
    const a = s.annotation || {};
    const ann = annotationBody(s, { tags: projects });
    try { await api(`/api/secrets/${encodeURIComponent(s.id)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann) }); s.annotation = Object.assign({}, a, ann); renderDrawer(); render(); }
    catch (e) { setToast("Couldn't update: " + e.message, true); }
  }

  function renderNotes(s) {
    const a = s.annotation || {};
    const form = el("div", { class: "form" });
    form.appendChild(noteField("Where did this come from?", "source_url", a.source_url, "e.g. dashboard.stripe.com", "A link to where this key was created."));
    form.appendChild(noteField("Where do you replace it?", "rotate_url", a.rotate_url, "link to make a new one", "Where you'd go to rotate it."));
    const exp = el("input", { type: "date" }); exp.value = a.expires_at || ""; exp.dataset.field = "expires_at"; exp.addEventListener("input", scheduleSave);
    form.appendChild(el("label", {}, [ el("div", { class: "lbl" }, [ document.createTextNode("Expires"), el("span", { class: "help", title: "Optional. We’ll float it into “Worth a look” as the date nears.", text: "?" }) ]), exp ]));
    form.appendChild(noteField("What can it do? (scope)", "scope", a.scope, "e.g. read-only · full access", "Optional. The key’s permissions — handy when deciding what to rotate first."));
    form.appendChild(noteField("Notes", "notes", a.notes, "anything future-you should know", null, true));
    form.appendChild(el("div", { class: "save-state", id: "save-state" }));
    const href = safeUrl(a.rotate_url);
    if (href) form.appendChild(el("a", { href, target: "_blank", rel: "noopener noreferrer" }, [ el("button", { class: "btn primary sm", text: "Go replace it ↗" }) ]));
    return form;
  }
  function noteField(label, name, value, ph, help, ta) {
    const lbl = el("div", { class: "lbl" }, [ document.createTextNode(label), help ? el("span", { class: "help", title: help, text: "?" }) : null ]);
    const input = ta ? el("textarea", { placeholder: ph }) : el("input", { type: "text", placeholder: ph });
    input.value = value || ""; input.dataset.field = name; input.addEventListener("input", scheduleSave);
    return el("label", {}, [ lbl, input ]);
  }
  function scheduleSave() { if (saveTimer) clearTimeout(saveTimer); setSaveState("saving"); saveTimer = setTimeout(saveAnnotation, 600); }
  function setSaveState(st) { saveState = st; const e = document.getElementById("save-state"); if (!e) return; e.className = "save-state " + (st === "idle" ? "" : st); e.textContent = st === "saving" ? "saving…" : st === "saved" ? "saved ✓" : st === "err" ? "couldn't save" : ""; }
  async function saveAnnotation() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    const ann = annotationBody(s, {});
    for (const f of drawerRoot.querySelectorAll("[data-field]")) ann[f.dataset.field] = f.value;
    try { await api(`/api/secrets/${encodeURIComponent(selectedId)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann) }); if (s) s.annotation = Object.assign({}, s.annotation, ann); setSaveState("saved"); setTimeout(() => { if (saveState === "saved") setSaveState("idle"); }, 1800); }
    catch (e) { setSaveState("err"); setToast("Couldn't save notes: " + e.message, true); }
  }
  async function markStale(id) { try { await api(`/api/secrets/${encodeURIComponent(id)}/stale`, { method: "POST" }); setToast("Marked not in use."); await loadSecrets(); renderDrawer(); } catch (e) { setToast("Couldn't update: " + e.message, true); } }
  async function markRotated(id) { try { await api(`/api/secrets/${encodeURIComponent(id)}/rotated`, { method: "POST" }); setToast("Noted — you replaced it."); await loadSecrets(); renderDrawer(); } catch (e) { setToast("Couldn't update: " + e.message, true); } }

  function closeModal() { clear(modalRoot); }

  // ---- utils -----------------------------------------------------------
  function prettyPath(p) { if (!p) return ""; const h = state.scan_home; return (h && p.indexOf(h) === 0) ? "~" + p.slice(h.length) : p; }
  function dirOf(p) { const i = p.lastIndexOf("/"); return i > 0 ? p.slice(0, i) : p; }
  function splitPath(p) { const s = prettyPath(p); const i = s.lastIndexOf("/"); return { dir: i >= 0 ? s.slice(0, i + 1) : "", base: i >= 0 ? s.slice(i + 1) : s }; }
  function spell(n) { return ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve"][n] || String(n); }
  function cap(s) { return s; }
  function copy(t, m) { const d = () => setToast(m || "Copied"); if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(d).catch(() => fb(t, d)); else fb(t, d); }
  function fb(t, d) { const ta = el("textarea", { style: "position:fixed;opacity:0" }); ta.value = t; document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); d(); } catch (_) { setToast("Couldn't copy", true); } document.body.removeChild(ta); }
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function shQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  function safeUrl(u) { if (!u) return null; try { const p = new URL(u, location.href); return (p.protocol === "http:" || p.protocol === "https:") ? p.href : null; } catch (_) { return null; } }

  // ---- live + chrome ---------------------------------------------------
  function startEvents() { const es = new EventSource("/api/events"); ["secret_created", "secret_refreshed", "secret_drifted"].forEach((t) => es.addEventListener(t, () => loadSecrets())); es.addEventListener("scan_started", () => setScanning(true)); es.addEventListener("scan_complete", () => { setScanning(false); loadSecrets(); }); es.onerror = () => {}; }
  function setScanning(on) { scanStatus.classList.toggle("scanning", on); scanStatusText.textContent = on ? "checking…" : "watching for changes"; }
  function startHeartbeat() { setInterval(() => { fetch("/api/heartbeat", { method: "POST", credentials: "same-origin" }).catch(() => {}); }, 30000); window.addEventListener("pagehide", () => navigator.sendBeacon("/api/close")); }
  function wireTheme() {
    const saved = localStorage.getItem("rafter.theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
    document.getElementById("theme-toggle").addEventListener("click", () => {
      const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next; localStorage.setItem("rafter.theme", next);
    });
  }
  function wireViewToggle() { const tg = document.getElementById("view-toggle"); for (const b of tg.querySelectorAll("button")) { b.addEventListener("click", () => { view = b.getAttribute("data-view"); localStorage.setItem("rafter.view", view); for (const o of tg.querySelectorAll("button")) o.classList.toggle("active", o === b); render(); }); b.classList.toggle("active", b.getAttribute("data-view") === view); } }

  const ICON = {
    file: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4 1.5h5l3 3v10H4z"/><path d="M9 1.5v3h3"/></svg>',
    lock: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="3" y="7" width="10" height="7" rx="1.2"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/></svg>',
    warn: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2 1.5 14h13z"/><path d="M8 6.5v3.5" stroke-linecap="round"/><circle cx="8" cy="12" r=".7" fill="currentColor" stroke="none"/></svg>',
    check: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 8.5 6.5 12 13 4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    copy: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5" y="5" width="8" height="9" rx="1.2"/><path d="M3 11V3a1 1 0 0 1 1-1h6"/></svg>',
    spark: '<svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1l1.5 4.3L14 7l-4.5 1.7L8 13l-1.5-4.3L2 7l4.5-1.7z"/></svg>',
    chev: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 4l4 4-4 4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    shield: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 1.5 13 3.5v4c0 3.5-2.2 5.8-5 7-2.8-1.2-5-3.5-5-7v-4z"/></svg>',
    x: '<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4l8 8M12 4l-8 8" stroke-linecap="round"/></svg>',
    repo: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3.5 2h7a1 1 0 0 1 1 1v11l-4-2-4 2V3a1 1 0 0 1 1-1z"/></svg>',
    muted: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8s2.2-4 6-4 6 4 6 4-2.2 4-6 4a6.5 6.5 0 0 1-3-.7"/><path d="M2 2l12 12"/></svg>',
    term: '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1.5" y="2.5" width="13" height="11" rx="1.5"/><path d="M4 6l2.5 2L4 10M8.5 10.5H12"/></svg>',
    folder: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"><path d="M1.5 4.5a1 1 0 0 1 1-1H6l1.5 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H2.5a1 1 0 0 1-1-1z"/></svg>',
  };

  // ---- scan scope panel ------------------------------------------------
  // Lets the user see and adjust which folders Rafter looks in — the
  // onboarding/scope step, in the browser instead of a terminal wizard.
  async function openScopePanel() {
    let data;
    try { data = await api("/api/scan-config"); }
    catch (e) { setToast("Couldn't load your scan scope: " + e.message, true); return; }
    const roots = (data.roots || []).slice();
    const home = data.home || "";
    const pretty = (p) => (home && p.indexOf(home) === 0) ? "~" + p.slice(home.length) : p;
    const modal = el("div", { class: "modal" });

    function add(p) { p = (p || "").trim(); if (p && roots.indexOf(p) < 0) roots.push(p); }
    function redraw() {
      clear(modal);
      modal.appendChild(el("div", { class: "mhead" }, [ el("h2", { text: "Where Rafter looks" }), el("button", { class: "btn ghost sm mclose", onclick: closeModal, text: "✕" }) ]));
      modal.appendChild(el("p", { class: "msub", text: "Rafter scans these folders on your computer for secrets. Nothing is changed, moved, or uploaded — it only reads." }));

      const list = el("div", { class: "scope-list" });
      if (!roots.length) list.appendChild(el("div", { class: "scope-empty", text: "No folders yet — add one below." }));
      for (const r of roots) {
        list.appendChild(el("div", { class: "scope-row" }, [
          el("span", { class: "ci", html: ICON.folder }),
          el("span", { class: "scope-path mono", text: pretty(r) }),
          el("button", { class: "btn ghost sm", title: "Remove", html: ICON.x, onclick: () => { const i = roots.indexOf(r); if (i >= 0) roots.splice(i, 1); redraw(); } }),
        ]));
      }
      modal.appendChild(list);

      const input = el("input", { class: "scope-input", type: "text", placeholder: "~/code   or   /full/path/to/a/folder" });
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(input.value); redraw(); } });
      modal.appendChild(el("div", { class: "scope-add" }, [ input, el("button", { class: "btn sm", text: "Add", onclick: () => { add(input.value); redraw(); } }) ]));

      const suggested = (data.suggested || []).filter((d) => roots.indexOf(d) < 0);
      if (suggested.length) {
        const row = el("div", { class: "suggests" }, [ el("span", { class: "slabel", text: "Suggested" }) ]);
        for (const d of suggested) {
          const c = el("span", { class: "tag suggest" }, [ el("span", { class: "gh", html: ICON.folder }), document.createTextNode(pretty(d)) ]);
          c.addEventListener("click", () => { add(d); redraw(); });
          row.appendChild(c);
        }
        modal.appendChild(row);
      }

      modal.appendChild(el("div", { class: "helpcard", html: "<b>Automatically skipped:</b> caches, <code>node_modules</code>, <code>.git</code>, build folders, and system files — so scans stay fast and focused." }));
      modal.appendChild(el("div", { class: "mactions" }, [
        el("button", { class: "btn sm", onclick: closeModal, text: "Cancel" }),
        el("button", { class: "btn primary sm", onclick: () => saveScope(roots, data.excludes), text: "Save & re-scan" }),
      ]));
    }
    redraw();
    clear(modalRoot);
    modalRoot.appendChild(el("div", { class: "modal-wrap", onclick: (e) => { if (e.target.classList.contains("modal-wrap")) closeModal(); } }, [ modal ]));
  }
  async function saveScope(roots, excludes) {
    if (!roots.length) { setToast("Add at least one folder to scan.", true); return; }
    try {
      await api("/api/scan-config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ roots, excludes: excludes || [] }) });
      closeModal(); setToast("Saved — re-scanning your folders…"); setScanning(true);
    } catch (e) { setToast("Couldn't save: " + e.message, true); }
  }

  // ---- "how do I run this?" — terminal-handoff explainers ---------------
  // The web UI never runs commands (read-only by design); these teach a
  // novice how to run the one the UI handed them, or to delegate it.
  function howToRun(whatItDoes) {
    return el("details", { class: "howto" }, [
      el("summary", {}, [ el("span", { class: "ci", html: ICON.term }), document.createTextNode("How do I run this?") ]),
      el("ol", {}, [
        el("li", { html: "Open <b>Terminal</b>: press <span class=\"kbd\">⌘ Space</span>, type <i>Terminal</i>, press Enter. (On Linux, open your terminal app.)" }),
        el("li", { html: "Paste the command you just copied — <span class=\"kbd\">⌘ V</span> (Mac) or <span class=\"kbd\">Ctrl ⇧ V</span> (Linux)." }),
        el("li", { html: "Press <span class=\"kbd\">Enter</span>." }),
      ]),
      whatItDoes ? el("div", { class: "note", text: whatItDoes }) : null,
      el("div", { class: "note", html: "Rather not touch the terminal? Ask your AI coding agent to run it — or give it the skill: <code>npx skills add Raftersecurity/rafter-secrets</code>." }),
    ]);
  }
  function rotateGuide(s) {
    const keyArg = /^[A-Za-z0-9_.-]+$/.test(s.key_name) ? s.key_name : shQuote(s.key_name);
    const cmd = "printf 'paste-the-new-value' | rafter-secrets rotate " + keyArg;
    const vendor = safeUrl((s.annotation || {}).rotate_url);
    return el("details", { class: "howto guide" }, [
      el("summary", {}, [ el("span", { class: "ci", html: ICON.term }), document.createTextNode("How do I replace this key?") ]),
      el("ol", {}, [
        el("li", {}, [ el("span", { html: "Make a <b>new key</b> on the provider’s site" }), vendor ? el("span", { html: " (<a href=\"" + escapeHtml(vendor) + "\" target=\"_blank\" rel=\"noopener noreferrer\">open it ↗</a>)" }) : document.createTextNode(" (e.g. your Stripe / AWS / OpenAI dashboard)"), document.createTextNode(". Copy the new value.") ]),
        el("li", {}, [ document.createTextNode("Swap it in — replace ‘paste-the-new-value’ with your new key and run this in Terminal:"),
          el("div", { class: "cmdrow" }, [ el("code", { text: cmd }), el("button", { class: "btn sm", onclick: () => copy(cmd, "Command copied"), text: "Copy" }) ]) ]),
        el("li", { html: "It shows what would change first; add <code>--yes</code> to apply. Every copy updates at once, each file is backed up, and <code>rafter-secrets undo</code> reverses it." }),
        el("li", { html: "Once the new key works, <b>turn off the old one</b> on the provider’s site." }),
      ]),
      el("div", { class: "note", text: "You type the new value straight into the tool — it never passes through this page or any AI agent." }),
    ]);
  }

  // ---- boot ------------------------------------------------------------
  document.getElementById("scope-btn").addEventListener("click", openScopePanel);
  document.getElementById("tour-btn").addEventListener("click", startWalkthrough);
  document.getElementById("search").addEventListener("input", (e) => { searchQ = e.target.value.trim().toLowerCase(); focus = null; render(); });
  document.addEventListener("keydown", (e) => { if (e.key !== "Escape") return; if (modalRoot.firstChild) closeModal(); else if (selectedId) closeDrawer(); });
  wireTheme(); wireViewToggle(); loadSecrets(); startEvents(); startHeartbeat();
})();
