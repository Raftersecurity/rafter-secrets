#!/usr/bin/env python3
"""Distill betterleaks' config/betterleaks.toml into the detection-only ruleset
Rafter vendors (internal/classify/rules/betterleaks.rules.json).

Keeps per rule: id, kw (keywords, lowercased), re (RE2 regex), ent (entropy
floor — from a top-level `entropy =` field or a `filter` of the form
`entropy(finding["secret"]) <= X`). Drops descriptions, tags, complex CEL
filters, and every `validate` clause (the upstream liveness HTTP-with-secret
check — Rafter never transmits secret values).

Usage: python3 scripts/distill-betterleaks.py /path/to/betterleaks.toml > out.json
"""
import json
import re
import sys
import tomllib

ENT_FLOOR = re.compile(r'entropy\(finding\["secret"\]\)\s*<=\s*([0-9.]+)')


def main() -> int:
    with open(sys.argv[1], "rb") as f:
        data = tomllib.load(f)
    out = []
    for r in data.get("rules", []):
        rx = r.get("regex")
        if not rx:
            continue
        floor = float(r["entropy"]) if isinstance(r.get("entropy"), (int, float)) else 0.0
        filt = r.get("filter")
        if filt:
            m = ENT_FLOOR.search(filt)
            if m:
                floor = max(floor, float(m.group(1)))
        out.append({
            "id": r.get("id", ""),
            "kw": [k.lower() for k in r.get("keywords", [])],
            "re": rx,
            "ent": floor,
        })
    json.dump(out, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
