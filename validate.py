#!/usr/bin/env python3
"""Validate a SCAFU Recon findings.json. Usage: python3 validate.py findings.json
Exit 0 if valid, 1 with one error per line otherwise. gen.py runs this before rendering."""
import datetime as dt, json, re, sys

SEVERITIES = {"critical", "high", "medium", "low", "info", "informational", "crit", "med", "moderate", "information"}
HIGHISH = {"critical", "crit", "high"}
BASES = {"observed", "inferred"}
CONF = {"high", "medium", "low"}
CHECK_STATUS = {"ok", "failed", "skipped"}
APP_TYPES = {"records", "table", "raw"}
TOP = {"target": str, "date": str, "authorized_by": str, "scope": (str, list), "methods": list,
       "out_of_scope": list, "findings": list, "strengths": list, "unverified": list, "limitations": list,
       "appendix": list, "check_log": list, "grade": str, "tagline": str, "summary": (str, list),
       "prepared_by": str, "version": str, "assessment_type": str, "example": bool, "_comment": str, "brand": dict}
FIELDS = {"id": str, "key": str, "severity": str, "title": str, "description": str, "evidence": str, "impact": str,
          "remediation": (list, str), "status": str, "action": str, "basis": str, "confidence": (str, int, float),
          "claimed_severity": str, "cve": (str, list)}

def slug(s): return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")

HEX = re.compile(r"^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
BRAND_KEYS = {"name", "url", "eyebrow", "wordmark", "logo", "colors", "powered_by"}
COLOR_KEYS = {"dark", "dark_deep", "on_dark", "accent", "accent_text", "ink"}

def validate_brand(b):
    """Validate a (merged) brand block. Returns a list of errors."""
    e = []
    if not isinstance(b, dict): return ["must be an object"]
    for k in b:
        if not k.startswith("_") and k not in BRAND_KEYS: e.append(f"unknown field {k!r}")
    if not isinstance(b.get("name"), str) or not b.get("name", "").strip(): e.append("name: required string")
    if not isinstance(b.get("url"), str) or not re.match(r"^https?://", b.get("url") or ""): e.append("url: must be an http(s) URL")
    if b.get("eyebrow") is not None and not isinstance(b["eyebrow"], str): e.append("eyebrow: must be a string")
    if b.get("logo") is not None and not (isinstance(b["logo"], str) and not re.match(r"^[a-z]+://", b["logo"], re.I) and re.search(r"\.(svg|png|jpe?g|webp)$", b["logo"], re.I)):
        e.append("logo: must be a local .svg/.png/.jpg/.webp path (it is embedded; no remote URLs)")
    wm = b.get("wordmark")
    if wm is not None and not (isinstance(wm, dict) and all(isinstance(wm.get(k, ""), str) for k in ("text", "accent"))):
        e.append("wordmark: must be {text, accent}")
    c = b.get("colors")
    if not isinstance(c, dict): e.append("colors: required object")
    else:
        for k in COLOR_KEYS - {"dark_deep"}:
            if k not in c: e.append(f"colors.{k}: required")
        for k, v in c.items():
            if k not in COLOR_KEYS: e.append(f"colors: unknown colour {k!r}")
            elif not (isinstance(v, str) and HEX.match(v)): e.append(f"colors.{k}: {v!r} is not a #hex colour")
    pb = b.get("powered_by")
    if pb not in (None, False) and not isinstance(pb, str):
        if not (isinstance(pb, dict) and isinstance(pb.get("text"), str) and re.match(r"^https?://", str(pb.get("url", "")))):
            e.append("powered_by: must be false, a string, or {text, url (http/https)}")
    return e

def validate(d):
    e = []
    if not isinstance(d, dict): return ["root: must be a JSON object"]
    for k, v in d.items():
        if k.startswith("_"): continue
        if k not in TOP: e.append(f"root: unknown field {k!r}")
        elif not isinstance(v, TOP[k]): e.append(f"{k}: wrong type ({type(v).__name__})")
    if not d.get("target") or not isinstance(d.get("target"), str): e.append("target: required non-empty string")
    if isinstance(d.get("date"), str):
        try: dt.date.fromisoformat(d["date"])
        except ValueError: e.append(f"date: {d['date']!r} is not YYYY-MM-DD")
    if isinstance(d.get("grade"), str) and d["grade"].strip().upper()[:1] not in "ABCDF" or d.get("grade") == "":
        e.append(f"grade: must be A-F, got {d['grade']!r}")
    if "brand" in d and isinstance(d["brand"], dict):
        import json as _j, os as _o
        base = _j.load(open(_o.path.join(_o.path.dirname(_o.path.abspath(__file__)), "brand.json")))
        def _m(a, b):
            o = dict(a)
            for k, v in b.items(): o[k] = _m(o[k], v) if isinstance(v, dict) and isinstance(o.get(k), dict) else v
            return o
        e += ["brand: " + x for x in validate_brand(_m(base, d["brand"]))]
    ids, keys = set(), set()
    for i, f in enumerate(d.get("findings") or [] if isinstance(d.get("findings"), list) else []):
        p = f"findings[{i}]"
        if not isinstance(f, dict): e.append(f"{p}: must be an object"); continue
        for k, v in f.items():
            if k.startswith("_"): continue
            if k not in FIELDS: e.append(f"{p}: unknown field {k!r}")
            elif not isinstance(v, FIELDS[k]) or isinstance(v, bool): e.append(f"{p}.{k}: wrong type ({type(v).__name__})")
        if not isinstance(f.get("title"), str) or not f.get("title", "").strip(): e.append(f"{p}.title: required")
        sev = str(f.get("severity", "")).lower()
        if sev not in SEVERITIES: e.append(f"{p}.severity: {f.get('severity')!r} not one of critical|high|medium|low|info")
        if "claimed_severity" in f and str(f["claimed_severity"]).lower() not in SEVERITIES:
            e.append(f"{p}.claimed_severity: invalid {f['claimed_severity']!r}")
        basis = str(f.get("basis", "observed")).lower()
        if basis not in BASES: e.append(f"{p}.basis: {f.get('basis')!r} not observed|inferred")
        if basis == "inferred" and sev in HIGHISH:
            e.append(f"{p}: inferred finding (version/fingerprint match) cannot be {sev}; set severity to medium or lower "
                     f"and record the original as claimed_severity (or run gen.py with --auto-cap)")
        if f.get("cve") and basis != "inferred":
            e.append(f"{p}: CVE matches from version strings/fingerprints must have basis=inferred")
        c = f.get("confidence")
        if c is not None and not ((isinstance(c, str) and c.lower() in CONF) or (isinstance(c, (int, float)) and not isinstance(c, bool) and 0 <= c <= 1)):
            e.append(f"{p}.confidence: must be high|medium|low or a number 0-1")
        if f.get("id"):
            if f["id"] in ids: e.append(f"{p}.id: duplicate {f['id']!r}")
            ids.add(f["id"])
        k = f.get("key") or slug(f.get("title", ""))
        if k in keys: e.append(f"{p}.key: duplicate key {k!r} (set an explicit unique 'key')")
        keys.add(k)
    for i, s in enumerate(d.get("strengths") or []):
        if not (isinstance(s, str) or (isinstance(s, dict) and isinstance(s.get("title"), str))):
            e.append(f"strengths[{i}]: must be a string or {{title, detail}}")
    for i, u in enumerate(d.get("unverified") or []):
        if not (isinstance(u, str) or (isinstance(u, dict) and isinstance(u.get("item"), str))):
            e.append(f"unverified[{i}]: must be a string or {{item, reason, confirm?}}")
    for i, c in enumerate(d.get("check_log") or []):
        if not isinstance(c, dict) or not isinstance(c.get("check"), str): e.append(f"check_log[{i}]: needs a 'check' string"); continue
        if c.get("status") not in CHECK_STATUS: e.append(f"check_log[{i}].status: {c.get('status')!r} not ok|failed|skipped")
    for i, a in enumerate(d.get("appendix") or []):
        if not isinstance(a, dict): e.append(f"appendix[{i}]: must be an object"); continue
        t = a.get("type", "raw")
        if t not in APP_TYPES: e.append(f"appendix[{i}].type: {t!r} not records|table|raw")
        c = a.get("content")
        if t == "table" and not (isinstance(c, dict) and isinstance(c.get("columns"), list) and isinstance(c.get("rows"), list)):
            e.append(f"appendix[{i}].content: table needs {{columns: [], rows: [[]]}}")
        if t == "records" and not isinstance(c, (dict, list)): e.append(f"appendix[{i}].content: records needs an object or [[k,v]]")
    return e

def main():
    if len(sys.argv) != 2: sys.exit(__doc__)
    try: d = json.load(open(sys.argv[1]))
    except Exception as x: print(f"error: cannot read JSON: {x}"); sys.exit(1)
    errs = validate(d)
    for x in errs: print("error:", x)
    if errs: sys.exit(1)
    print("ok")

if __name__ == "__main__": main()
