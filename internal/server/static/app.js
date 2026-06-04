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
  const toastWrap = document.getElementById("toast-wrap");
  const scanStatus = document.getElementById("scan-status");
  const scanStatusText = document.getElementById("scan-status-text");

  let state = { secrets: [], scan_home: null };
  let selectedId = null;
  let view = localStorage.getItem("rafter.view") || "secret";
  const revealed = new Map();
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

  function parsePerm(p) { if (!p) return null; const m = /(\d{3,4})$/.exec(p); if (!m) return null; const o = m[1].slice(-3); return { group: (parseInt(o[1], 8) & 4) !== 0, other: (parseInt(o[2], 8) & 4) !== 0 }; }
  function isManual(s) { return typeof s.id === "string" && s.id.indexOf("manual:") === 0; }
  function fileLocations(s) { return (s.found_in || []).filter((f) => f.path && f.source_type !== "manual"); }
  function exposure(s) { let w = null; for (const f of fileLocations(s)) { const pm = parsePerm(f.permissions); if (!pm) continue; if (pm.other) return { level: "other", path: f.path }; if (pm.group && !w) w = { level: "group", path: f.path }; } return w; }
  function isDuplicated(s) { return fileLocations(s).length > 1; }
  function isStale(s) { return !!(s.annotation && s.annotation.stale); }
  function projectsOf(s) { return (s.annotation && s.annotation.tags) || []; }
  function needsAttention(s) { return !isStale(s) && (!!exposure(s) || isDuplicated(s)); }

  // ---- data ------------------------------------------------------------
  async function loadSecrets() {
    try {
      const body = await api("/api/secrets");
      state.secrets = body.secrets || [];
      const roots = (body.scan_config && body.scan_config.roots) || [];
      state.scan_home = roots.slice().sort((a, b) => a.length - b.length)[0] || null;
      render();
    } catch (e) {
      clear(content);
      content.appendChild(el("div", { class: "empty" }, [ el("div", { class: "ec", html: ICON.warn }), el("h3", { text: "Couldn't reach Rafter Secrets" }), el("p", { text: e.message + ". Try reloading." }) ]));
    }
  }

  // ---- render ----------------------------------------------------------
  function render() {
    clear(content);
    if (state.secrets.length === 0) { content.appendChild(renderEmpty()); content.appendChild(renderFoot()); return; }

    content.appendChild(renderHero());
    content.appendChild(renderFigures());

    const attn = state.secrets.filter(needsAttention);
    if (view === "folder") {
      content.appendChild(section("Where your secrets live", null, null));
      content.appendChild(renderFolder(state.secrets));
    } else if (view === "project") {
      renderProjects(state.secrets).forEach((n) => content.appendChild(n));
    } else {
      if (attn.length) {
        content.appendChild(section("Worth a look", attn.length, "we'd tidy these first"));
        content.appendChild(renderList(attn, true));
      }
      const rest = state.secrets.filter((s) => !needsAttention(s)).sort(byName);
      content.appendChild(section(attn.length ? "Everything else" : "Your secrets", rest.length, null));
      content.appendChild(renderList(rest, false));
    }
    content.appendChild(renderFoot());
    if (selectedId && !state.secrets.some((s) => s.id === selectedId)) closeDrawer();
  }
  function byName(a, b) { return vendorFor(a.key_name).name.localeCompare(vendorFor(b.key_name).name); }

  function renderHero() {
    const live = state.secrets.filter((s) => !isStale(s));
    const total = live.length;
    const attn = live.filter(needsAttention).length;
    const stmt = el("h1", { class: "statement" });
    if (attn > 0) {
      stmt.appendChild(el("span", { class: "grad", text: cap(spell(attn)) }));
      stmt.appendChild(document.createTextNode(" of your "));
      stmt.appendChild(el("span", { class: "num", text: String(total) }));
      stmt.appendChild(document.createTextNode(" saved secrets " + (attn === 1 ? "is " : "are ")));
      stmt.appendChild(el("b", { text: "worth a look" }));
      stmt.appendChild(document.createTextNode("."));
    } else {
      stmt.appendChild(document.createTextNode("All "));
      stmt.appendChild(el("span", { class: "num", text: String(total) }));
      stmt.appendChild(document.createTextNode(" of your saved secrets "));
      stmt.appendChild(el("b", { text: "look tidy" }));
      stmt.appendChild(document.createTextNode("."));
    }
    return el("div", { class: "hero" }, [
      el("div", { class: "eyebrow", text: "On this computer" }),
      stmt,
      el("p", { class: "lede", html: "Passwords, keys, and tokens sitting in plain files — readable by anything you run, <b>including AI coding agents</b>. Nothing here is changed, moved, or uploaded." }),
    ]);
  }

  function renderFigures() {
    const live = state.secrets.filter((s) => !isStale(s));
    const total = live.length;
    const exposed = live.filter((s) => exposure(s)).length;
    const dup = live.filter(isDuplicated).length;
    const priv = live.filter((s) => !exposure(s) && !isDuplicated(s) && (fileLocations(s).length > 0)).length;
    const pct = (n) => total ? Math.max(4, Math.round((n / total) * 100)) : 0;
    const wrap = el("div", { class: "figures" });
    wrap.appendChild(figure("Tracked", total, null, "ink", 100, "saved in plain files"));
    wrap.appendChild(figure("Exposed", exposed, exposed ? ["bad", "Action"] : ["ok", "Clear"], "red", pct(exposed), "readable by other apps"));
    wrap.appendChild(figure("In 2+ places", dup, dup ? ["warn", "Action"] : ["ok", "Good"], "amber", pct(dup), "easy to lose track of"));
    wrap.appendChild(figure("Private", priv, ["ok", "Good"], "green", pct(priv), "stored only for you"));
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
    const ex = exposure(s);
    let cls = "row";
    if (flagged) cls += ex && ex.level === "other" ? " flag danger" : " flag warn";
    if (isStale(s)) cls += " stale";
    const row = el("div", { class: cls });
    row.appendChild(el("div", { class: "tile", text: v.chip }));

    const sub = el("div", { class: "rsub" }, [ el("span", { text: contextLabel(s) }), el("span", { class: "sdot" }), el("code", { text: s.key_name }) ]);
    row.appendChild(el("div", { class: "rbody" }, [ el("div", { class: "rname", text: v.name }), sub ]));

    row.appendChild(el("div", { class: "rright" }, [ el("span", { class: "dots", text: "••••••" }), statusPill(s), el("span", { class: "chev", html: ICON.chev }) ]));
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
    if (isStale(s)) return pill("muted", "Not in use");
    const ex = exposure(s);
    if (ex && ex.level === "other") return pill("danger", "Any app can read this");
    if (ex && ex.level === "group") return pill("warn", "Readable by your group");
    if (isDuplicated(s)) return pill("info", "Saved in " + fileLocations(s).length + " places");
    if (isManual(s)) return pill("manual", "You're tracking this");
    return pill("ok", "Private to you");
  }
  function pill(cls, text) { return el("span", { class: "pill " + cls }, [ cls === "manual" ? null : el("span", { class: "pd" }), document.createTextNode(text) ]); }

  // ---- folder + project views -----------------------------------------
  function renderFolder(secrets) {
    const byDir = new Map();
    for (const s of secrets) { const f = fileLocations(s)[0]; const d = f ? prettyPath(dirOf(f.path)) : "(added by hand)"; if (!byDir.has(d)) byDir.set(d, []); byDir.get(d).push(s); }
    const frag = document.createDocumentFragment();
    for (const d of Array.from(byDir.keys()).sort()) {
      frag.appendChild(el("div", { class: "treepath", text: d + "/" }));
      frag.appendChild(renderList(byDir.get(d).sort(byName), false));
    }
    const box = el("div"); box.appendChild(frag); return box;
  }
  function renderProjects(secrets) {
    const groups = new Map(); const untagged = [];
    for (const s of secrets) { const ps = projectsOf(s); if (!ps.length) { untagged.push(s); continue; } for (const p of ps) { if (!groups.has(p)) groups.set(p, []); groups.get(p).push(s); } }
    const out = [];
    for (const name of Array.from(groups.keys()).sort()) { out.push(section(name, groups.get(name).length, null)); out.push(renderList(groups.get(name).sort(byName), false)); }
    if (untagged.length) { out.push(section("No project yet", untagged.length, "tag a secret to group it")); out.push(renderList(untagged.sort(byName), false)); }
    return out;
  }

  function renderEmpty() {
    return el("div", { class: "empty" }, [
      el("div", { class: "ec", html: ICON.check }),
      el("h3", { text: "Nothing saved in the open." }),
      el("p", { text: "Rafter Secrets didn't find any passwords or keys in plain files. It keeps watching — or add one yourself to start tracking it." }),
      el("button", { class: "btn primary", onclick: openAddSecret, text: "+ Add a secret" }),
    ]);
  }
  function renderFoot() {
    return el("div", { class: "foot" }, [ el("span", { class: "sh", html: ICON.shield }), el("span", { text: "This view only reads — it never changes your files. Anything that does change a file is a deliberate, previewed step you run from the command line. Nothing ever leaves this computer." }) ]);
  }

  // ---- reveal ----------------------------------------------------------
  async function toggleReveal(s) {
    if (revealed.has(s.id)) { revealed.delete(s.id); renderDrawer(); return; }
    try { const b = await api(`/api/secrets/${encodeURIComponent(s.id)}/reveal`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); revealed.set(s.id, b.value); renderDrawer(); }
    catch (e) { if (e.status === 422) setToast("No live value to show for this one.", true); else if (e.status === 410) setToast("That value just changed — refreshing.", true); else setToast("Couldn't read it: " + e.message, true); }
  }

  // ---- drawer ----------------------------------------------------------
  function openDrawer(id) { selectedId = id; renderDrawer(); }
  function closeDrawer() { selectedId = null; clear(drawerRoot); }
  function renderDrawer() {
    if (!selectedId) return;
    const s = state.secrets.find((x) => x.id === selectedId);
    if (!s) { closeDrawer(); return; }
    const v = vendorFor(s.key_name);
    clear(drawerRoot);
    const scrim = el("div", { class: "scrim", onclick: closeDrawer });
    const body = el("div", { class: "dscroll" });

    body.appendChild(el("div", { class: "dhead" }, [
      el("div", { class: "tile", text: v.chip }),
      el("div", { class: "dtitles" }, [ el("h2", { text: s.key_name }), el("div", { class: "dtype" }, [ el("span", { class: "em", text: v.name }), document.createTextNode(" · " + contextLabel(s).toLowerCase()) ]) ]),
      el("button", { class: "btn ghost sm mclose", onclick: closeDrawer, text: "✕" }),
    ]));

    const isRev = revealed.has(s.id);
    if (isManual(s)) body.appendChild(el("div", { class: "valuebox" }, [ el("span", { class: "v hidden", text: "added by you — no file value" }) ]));
    else body.appendChild(el("div", { class: "valuebox" }, [
      el("span", { class: "v " + (isRev ? "revealed" : "hidden"), text: isRev ? revealed.get(s.id) : "••••••••••••" }),
      isRev ? el("button", { class: "btn sm", onclick: () => copy(revealed.get(s.id), "Copied"), text: "Copy" }) : null,
      el("button", { class: "btn sm", onclick: () => toggleReveal(s), text: isRev ? "Hide" : "Show value" }),
    ]));

    const findings = buildFindings(s);
    body.appendChild(el("div", { class: "blk-h", text: "What this means" }));
    if (!findings.length) body.appendChild(el("div", { class: "finding ok" }, [ el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.check }), document.createTextNode(isManual(s) ? "Tracked by you." : "Looks fine.") ]), el("p", { class: "fb", text: isManual(s) ? "You added this by hand. Keep a note of where it lives below." : "Stored in a file only you can read, and only found in one place." }) ]));
    else findings.forEach((f) => body.appendChild(f));

    body.appendChild(el("div", { class: "blk-h", text: "Projects" }));
    body.appendChild(renderProjectEditor(s));

    if (!isManual(s) || (s.found_in || []).length) { body.appendChild(el("div", { class: "blk-h", text: "Where it's stored" })); body.appendChild(renderLocations(s)); }

    body.appendChild(el("div", { class: "blk-h", text: "Notes" }));
    body.appendChild(renderNotes(s));

    body.appendChild(el("div", { class: "dactions" }, [
      el("button", { class: "btn sm", title: "Record that you've replaced this with a new one (do the replacing yourself first).", onclick: () => markRotated(s.id), text: "I've replaced this" }),
      isStale(s) ? el("button", { class: "btn sm", disabled: "", text: "Marked not in use" }) : el("button", { class: "btn sm", onclick: () => markStale(s.id), text: "I don't use this" }),
    ]));

    drawerRoot.appendChild(scrim);
    drawerRoot.appendChild(el("div", { class: "drawer" }, [ body ]));
  }

  function buildFindings(s) {
    const out = [];
    const ex = exposure(s);
    if (ex) {
      const danger = ex.level === "other";
      out.push(el("div", { class: "finding " + (danger ? "danger" : "warn") }, [
        el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.warn }), document.createTextNode(danger ? "Any app or AI agent can read it" : "Your group can read it") ]),
        el("p", { class: "fb", html: danger
          ? "The file <code>" + escapeHtml(splitPath(ex.path).base) + "</code> is readable by <b>any program you run</b>, including AI coding agents. On a shared machine, tighten it."
          : "Other accounts in your group can read <code>" + escapeHtml(splitPath(ex.path).base) + "</code>." }),
        el("div", { class: "fact" }, [ el("button", { class: "btn sm", onclick: () => copy("chmod 600 " + shQuote(ex.path), "Command copied"), text: "Copy the fix" }), el("span", { class: "hint", text: "makes it yours only" }) ]),
      ]));
    }
    if (isDuplicated(s)) out.push(el("div", { class: "finding warn" }, [ el("div", { class: "fh" }, [ el("span", { class: "fi", html: ICON.copy }), document.createTextNode("Saved in " + fileLocations(s).length + " files") ]), el("p", { class: "fb", text: "Replace it once and you'll need to update every copy, or the apps using the old ones break." }) ]));
    return out;
  }

  function renderLocations(s) {
    const ul = el("ul", { class: "locs" });
    for (const f of s.found_in || []) {
      if (!f.path && !f.keystore) continue;
      const sp = f.path ? splitPath(f.path) : { dir: "", base: "" };
      const pm = parsePerm(f.permissions);
      let ls = null;
      if (f.source_type === "manual") ls = el("div", { class: "ls", text: "you noted this" });
      else if (f.keystore) ls = el("div", { class: "ls", text: "system keyring · viewing here is coming soon" });
      else { const parts = []; if (pm && pm.other) parts.push(el("span", { class: "warnflag", text: "any app can read it" })); else if (pm && pm.group) parts.push(el("span", { class: "warnflag group", text: "your group can read it" })); else parts.push(document.createTextNode("private to you")); ls = el("div", { class: "ls" }, parts); }
      ul.appendChild(el("li", {}, [ el("span", { class: "li-ico", html: f.keystore ? ICON.lock : ICON.file }), el("div", { style: "min-width:0" }, [ el("div", { class: "lp", text: f.path ? prettyPath(f.path) : keystoreName(f.keystore) }), ls ]) ]));
    }
    return ul;
  }
  function keystoreName(k) { return /keychain/i.test(k) ? "macOS Keychain" : "System keyring"; }

  function renderProjectEditor(s) {
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
    return wrap;
  }
  async function setProjects(s, projects) {
    const a = s.annotation || {};
    const ann = { source_url: a.source_url || "", owner: a.owner || "", notes: a.notes || "", rotate_url: a.rotate_url || "", tags: projects };
    try { await api(`/api/secrets/${encodeURIComponent(s.id)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann) }); s.annotation = Object.assign({}, a, ann); renderDrawer(); render(); }
    catch (e) { setToast("Couldn't update: " + e.message, true); }
  }

  function renderNotes(s) {
    const a = s.annotation || {};
    const form = el("div", { class: "form" });
    form.appendChild(noteField("Where did this come from?", "source_url", a.source_url, "e.g. dashboard.stripe.com", "A link to where this key was created."));
    form.appendChild(noteField("Where do you replace it?", "rotate_url", a.rotate_url, "link to make a new one", "Where you'd go to rotate it."));
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
    const ann = { source_url: "", owner: "", notes: "", rotate_url: "", tags: projectsOf(s) };
    for (const f of drawerRoot.querySelectorAll("[data-field]")) ann[f.dataset.field] = f.value;
    try { await api(`/api/secrets/${encodeURIComponent(selectedId)}/annotation`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ann) }); if (s) s.annotation = Object.assign({}, s.annotation, ann); setSaveState("saved"); setTimeout(() => { if (saveState === "saved") setSaveState("idle"); }, 1800); }
    catch (e) { setSaveState("err"); setToast("Couldn't save notes: " + e.message, true); }
  }
  async function markStale(id) { try { await api(`/api/secrets/${encodeURIComponent(id)}/stale`, { method: "POST" }); setToast("Marked not in use."); await loadSecrets(); renderDrawer(); } catch (e) { setToast("Couldn't update: " + e.message, true); } }
  async function markRotated(id) { try { await api(`/api/secrets/${encodeURIComponent(id)}/rotated`, { method: "POST" }); setToast("Noted — you replaced it."); await loadSecrets(); renderDrawer(); } catch (e) { setToast("Couldn't update: " + e.message, true); } }

  // ---- add a secret ----------------------------------------------------
  function openAddSecret() {
    const f = {};
    const field = (label, key, ph, help, ta) => { const input = ta ? el("textarea", { placeholder: ph }) : el("input", { type: "text", placeholder: ph }); f[key] = input; return el("label", {}, [ el("div", { class: "lbl" }, [ document.createTextNode(label), help ? el("span", { class: "help", title: help, text: "?" }) : null ]), input ]); };
    const modal = el("div", { class: "modal" }, [
      el("div", { class: "mhead" }, [ el("h2", { text: "Add a secret to track" }), el("button", { class: "btn ghost sm mclose", onclick: closeModal, text: "✕" }) ]),
      el("p", { class: "msub", text: "For a key you keep elsewhere — a password manager, a vendor dashboard — or want to track before it's scanned." }),
      el("div", { class: "helpcard", html: "<b>Worth tracking:</b> API keys & tokens (Stripe, OpenAI, GitHub…), database & service passwords, cloud credentials, signing & SSH keys. Note <b>where it came from</b>, <b>where to replace it</b>, and its <b>project</b>." }),
      el("div", { class: "form" }, [
        field("Name", "key_name", "e.g. STRIPE_LIVE_KEY", "What you'll recognise it by."),
        field("Project", "project", "e.g. naledi  (optional)", "Group it with related secrets."),
        field("Where does it live?", "path", "e.g. ~/code/app/.env  (optional)", "Just a note — nothing is opened."),
        field("Where do you replace it?", "rotate_url", "https://…  (optional)", null),
        field("Notes", "notes", "optional", null, true),
      ]),
      el("div", { class: "mactions" }, [ el("button", { class: "btn sm", onclick: closeModal, text: "Cancel" }), el("button", { class: "btn primary sm", onclick: () => submitAdd(f), text: "Add secret" }) ]),
    ]);
    clear(modalRoot); modalRoot.appendChild(el("div", { class: "modal-wrap", onclick: (e) => { if (e.target.classList.contains("modal-wrap")) closeModal(); } }, [ modal ]));
    f.key_name.focus();
  }
  function closeModal() { clear(modalRoot); }
  async function submitAdd(f) {
    const key_name = f.key_name.value.trim();
    if (!key_name) { f.key_name.focus(); setToast("Give it a name first.", true); return; }
    const project = f.project.value.trim();
    try { const created = await api("/api/secrets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key_name, path: f.path.value.trim(), annotation: { source_url: "", owner: "", notes: f.notes.value.trim(), rotate_url: f.rotate_url.value.trim(), tags: project ? [project] : [] } }) }); closeModal(); setToast("Added " + key_name + "."); await loadSecrets(); if (created && created.id) openDrawer(created.id); }
    catch (e) { setToast("Couldn't add it: " + e.message, true); }
  }

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
    chev: '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 4l4 4-4 4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    shield: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 1.5 13 3.5v4c0 3.5-2.2 5.8-5 7-2.8-1.2-5-3.5-5-7v-4z"/></svg>',
    x: '<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4l8 8M12 4l-8 8" stroke-linecap="round"/></svg>',
  };

  // ---- boot ------------------------------------------------------------
  document.getElementById("add-secret-btn").addEventListener("click", openAddSecret);
  document.addEventListener("keydown", (e) => { if (e.key !== "Escape") return; if (modalRoot.firstChild) closeModal(); else if (selectedId) closeDrawer(); });
  wireTheme(); wireViewToggle(); loadSecrets(); startEvents(); startHeartbeat();
})();
