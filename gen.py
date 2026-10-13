#!/usr/bin/env python3
"""SCAFU Recon report generator (data-driven, brandable; default brand SCAFU).

Usage:  python3 gen.py findings.json --out <dir>
Writes <dir>/report.html, report.pdf (headless Chrome/Chromium), preview-1.png, preview-2.png.
Schema and grading rubric: see schema.md next to this file.
"""
import argparse, copy, base64, datetime as dt, html, json, os, re, shutil, subprocess, sys
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate

HERE = os.path.dirname(os.path.abspath(__file__))
E = lambda s: html.escape("" if s is None else str(s))
SEV = ["Critical", "High", "Medium", "Low", "Info"]
PREFIX = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Info": "I"}

# ------------------------------------------------------------------ rubric
WEIGHTS = {"Critical": 40, "High": 15, "Medium": 5, "Low": 1, "Info": 0}
BANDS = [("A", 90), ("B", 75), ("C", 60), ("D", 40), ("F", -10**9)]
TAGLINE = {"A": "Strong posture, minor polish only",
           "B": "Good, with hardening gaps",
           "C": "Fair, several gaps to address",
           "D": "Weak, significant risks present",
           "F": "Poor, urgent remediation required"}
OPENING = {"A": "is in strong shape",
           "B": "is in good shape overall",
           "C": "has a fair security posture with several gaps",
           "D": "has a weak external security posture",
           "F": "has serious, urgent security problems"}

def compute_grade(cnt):
    score = 100 - sum(WEIGHTS[s] * cnt[s] for s in SEV)
    grade = next(g for g, lo in BANDS if score >= lo)
    order = "ABCDF"
    if cnt["Critical"] >= 2: cap = "F"
    elif cnt["Critical"] == 1: cap = "D"
    elif cnt["High"] >= 1: cap = "C"
    else: cap = "A"
    if order.index(cap) > order.index(grade): grade = cap
    return grade, score

# ------------------------------------------------------------------ helpers
def norm_sev(s):
    s = str(s or "info").strip().lower()
    if s.capitalize() in SEV: return s.capitalize()
    m = {"critical": "Critical", "crit": "Critical", "high": "High", "medium": "Medium", "med": "Medium",
         "moderate": "Medium", "low": "Low", "info": "Info", "informational": "Info", "information": "Info"}
    if s not in m: raise ValidationError(f"unknown severity {s!r} (use critical|high|medium|low|info)")
    return m[s]

def as_list(x):
    if x is None: return []
    return x if isinstance(x, list) else [x]

def detail(s): return f"<p>{E(s['detail'])}</p>" if s.get("detail") else ""
def pill(s): return f'<span class="pill p-{s.lower()}"><i></i>{s}</span>'
def is_uv(st): return bool(st) and "unverif" in st.lower()
def css_str(s): return str(s).replace("\\", "\\\\").replace('"', '\\"')

def nice_date(s):
    try: return dt.date.fromisoformat(s).strftime("%B %-d, %Y")
    except Exception: return s

def join_and(xs):
    xs = list(xs)
    return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1] if xs else ""

NUMW = {0: "no", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}
def nw(n): return NUMW.get(n, str(n))

# ------------------------------------------------------------------ load + normalise
class ValidationError(Exception):
    pass

def auto_cap(d):
    """Downgrade inferred critical/high findings to medium, recording claimed_severity (used by --auto-cap)."""
    for f in d.get("findings") or []:
        if isinstance(f, dict) and str(f.get("basis", "")).lower() == "inferred" and norm_sev(f.get("severity")) in ("Critical", "High"):
            f.setdefault("claimed_severity", str(f["severity"]).lower()); f["severity"] = "medium"
    return d

def load(path, cap=False):
    return normalize(json.load(open(path)), cap=cap)

def normalize(d, cap=False):
    d = copy.deepcopy(d)
    if cap: auto_cap(d)
    errs = validate.validate(d)
    if errs: raise ValidationError("\n".join(errs))
    d.setdefault("date", dt.date.today().isoformat())
    F = []
    for i, f in enumerate(as_list(d.get("findings"))):
        basis = str(f.get("basis", "observed")).lower()
        sev = norm_sev(f.get("severity")); claimed = f.get("claimed_severity")
        if basis == "inferred" and sev in ("Critical", "High"):   # defensive; validate() normally rejects this
            claimed = claimed or sev; sev = "Medium"
        status = f.get("status")
        if basis == "inferred" and not is_uv(status): status = "Unverified"
        F.append(dict(key=f.get("key") or validate.slug(f["title"]), basis=basis, confidence=f.get("confidence"),
                      claimed_severity=norm_sev(claimed) if claimed else None, cve=as_list(f.get("cve")),
                      id=f.get("id"), severity=sev, title=f["title"],
                      description=f.get("description", ""), evidence=f.get("evidence", ""),
                      impact=f.get("impact", ""), remediation=as_list(f.get("remediation")),
                      status=status, action=f.get("action"), _i=i))
    F.sort(key=lambda f: (SEV.index(f["severity"]), f["_i"]))
    used = {f["id"] for f in F if f["id"]}
    nxt = Counter()
    for f in F:
        if f["id"]: continue
        p = PREFIX[f["severity"]]
        while True:
            nxt[p] += 1
            cand = f"{p}-{nxt[p]:02d}"
            if cand not in used: break
        f["id"] = cand; used.add(cand)
        if not f["status"]: f["status"] = None
    d["findings"] = F
    d["strengths"] = [s if isinstance(s, dict) else {"title": s, "detail": ""} for s in as_list(d.get("strengths"))]
    d["unverified"] = [u if isinstance(u, dict) else {"item": u, "reason": ""} for u in as_list(d.get("unverified"))]
    d["appendix"] = as_list(d.get("appendix"))
    d["check_log"] = as_list(d.get("check_log"))
    return d

# ------------------------------------------------------------------ fonts
def font_b64(rel):
    """Fonts are stored as base64 text (build/<name>.b64) so the repo stays text-only; a binary file also works."""
    p = os.path.join(HERE, rel)
    if os.path.isfile(p + ".b64"): return "".join(open(p + ".b64").read().split())
    return base64.b64encode(open(p, "rb").read()).decode()

# ------------------------------------------------------------------ brand
def hex_rgb(h):
    h = h.lstrip("#"); h = "".join(c * 2 for c in h) if len(h) == 3 else h
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

def merge(a, b):
    out = dict(a)
    for k, v in (b or {}).items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out

def load_brand(d, base_dir=None):
    """Default brand.json (SCAFU) deep-merged with the findings file's optional `brand` block."""
    b = merge(json.load(open(os.path.join(HERE, "brand.json"))), d.get("brand") or {})
    errs = validate.validate_brand(b)
    if errs: raise ValidationError("\n".join("brand: " + e for e in errs))
    b["logo_uri"] = None
    if b.get("logo"):
        cands = [b["logo"]] if os.path.isabs(b["logo"]) else [os.path.join(x, b["logo"]) for x in (base_dir, HERE) if x]
        path = next((c for c in cands if os.path.isfile(c)), None)
        if not path: raise ValidationError(f"brand: logo file not found: {b['logo']}")
        mime = {".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}[os.path.splitext(path)[1].lower()]
        b["logo_uri"] = f"data:{mime};base64," + base64.b64encode(open(path, "rb").read()).decode()
    pb = b.get("powered_by")
    if isinstance(pb, str): pb = {"text": pb, "url": b["url"]}
    b["powered_by"] = pb or None
    return b

def brand_vars(b):
    c = b["colors"]; r, g, bl = hex_rgb(c["on_dark"]); ar, ag, ab = hex_rgb(c["accent"])
    return ";".join([f"--navy:{c['dark']}", f"--navy-deep:{c.get('dark_deep', c['dark'])}", f"--ink:{c['ink']}",
                     f"--accent:{c['accent_text']}", f"--brand-accent:{c['accent']}", f"--on-dark:{c['on_dark']}",
                     f"--on-dark-soft:rgba({r},{g},{bl},.78)", f"--on-dark-muted:rgba({r},{g},{bl},.5)",
                     f"--on-dark-line:rgba({r},{g},{bl},.16)", f"--on-dark-faint:rgba({r},{g},{bl},.07)",
                     f"--glow:rgba({ar},{ag},{ab},.13)"])

def brand_mark(b):
    if b["logo_uri"]: inner = f'<img class="logo" src="{b["logo_uri"]}" alt="{E(b["name"])}">'
    else:
        wm = b.get("wordmark") or {"text": b["name"], "accent": ""}
        inner = f'<span class="wm">{E(wm.get("text", ""))}<b>{E(wm.get("accent", ""))}</b></span>'
    eb = f'<span class="eyebrow">{E(b["eyebrow"])}</span>' if b.get("eyebrow") else ""
    return f'<div class="brand"><a class="pby" href="{E(b["url"])}">{inner}</a>{eb}</div>'

def powered_html(b, cls):
    pb = b["powered_by"]
    return f'<div class="{cls}"><a href="{E(pb["url"])}">{E(pb["text"])}</a></div>' if pb else ""

# ------------------------------------------------------------------ history
GRADES = "ABCDF"

def effective_grade(d):
    cnt = Counter(f["severity"] for f in d["findings"])
    computed, score = compute_grade(cnt)
    return (d.get("grade") or computed).strip().upper()[:1], computed, score

def latest_snapshot(hdir):
    if not hdir or not os.path.isdir(hdir): return None
    snaps = sorted(f for f in os.listdir(hdir) if re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{6}(-\d+)?\.json", f))
    return os.path.join(hdir, snaps[-1]) if snaps else None

def diff(prev_raw, cur):
    """Compare a previous snapshot (raw JSON) with the current normalized data, matched by finding key."""
    meta = prev_raw.get("_snapshot", {})
    prev = normalize({k: v for k, v in prev_raw.items() if k != "_snapshot"})
    pg = meta.get("grade") or effective_grade(prev)[0]
    cg = effective_grade(cur)[0]
    P = {f["key"]: f for f in prev["findings"]}; C = {f["key"]: f for f in cur["findings"]}
    return {"prev_date": prev.get("date"), "prev_grade": pg, "grade": cg,
            "grade_delta": GRADES.index(pg) - GRADES.index(cg),   # >0 improved, <0 worse
            "new": [C[k] for k in C if k not in P],
            "resolved": [P[k] for k in P if k not in C],
            "changed": [(P[k], C[k]) for k in C if k in P and P[k]["severity"] != C[k]["severity"]],
            "unchanged": sum(1 for k in C if k in P and P[k]["severity"] == C[k]["severity"])}

def save_snapshot(raw, hdir, grade):
    os.makedirs(hdir, exist_ok=True)
    base = f'{raw.get("date") or dt.date.today().isoformat()}_{dt.datetime.now().strftime("%H%M%S")}'
    p, n = os.path.join(hdir, base + ".json"), 1
    while os.path.exists(p): p = os.path.join(hdir, f"{base}-{n}.json"); n += 1
    snap = {k: v for k, v in raw.items() if k != "_snapshot"}
    snap["_snapshot"] = {"saved_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "grade": grade}
    json.dump(snap, open(p, "w"), indent=1, ensure_ascii=False)
    return p

def changes_html(c):
    gd = c["grade_delta"]
    trend = "improved" if gd > 0 else "declined" if gd < 0 else "unchanged"
    head = (f'<p class="lead">Compared with the previous assessment on {E(c["prev_date"])} (PT), the grade has {trend}: '
            f'<b>{E(c["prev_grade"])} → {E(c["grade"])}</b>. {len(c["new"])} new, {len(c["resolved"])} resolved, '
            f'{len(c["changed"])} with changed severity, {c["unchanged"]} unchanged.</p>')
    cards = "".join(f'<div class="sc"><div class="n">{n}</div><div class="l">{l}</div></div>' for n, l in
                    [(f'{c["prev_grade"]}→{c["grade"]}', "Grade"), (len(c["new"]), "New"), (len(c["resolved"]), "Resolved"),
                     (len(c["changed"]), "Severity changed"), (c["unchanged"], "Unchanged")])
    out = head + f'<div class="counts">{cards}</div>'
    def tbl(title, rows, cols):
        if not rows: return ""
        return (f'<h3 class="sub">{title}</h3><table class="ft"><thead><tr>' + "".join(f"<th>{x}</th>" for x in cols) +
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
    out += tbl("New findings", [f'<tr><td class="mono id">{E(f["id"])}</td><td>{E(f["title"])}</td><td>{pill(f["severity"])}</td></tr>' for f in c["new"]], ["ID", "Finding", "Severity"])
    out += tbl("Resolved since last assessment", [f'<tr><td class="mono id">{E(f["id"])}</td><td>{E(f["title"])}</td><td>{pill(f["severity"])}</td></tr>' for f in c["resolved"]], ["Prev. ID", "Finding", "Was"])
    out += tbl("Severity changed", [f'<tr><td class="mono id">{E(b["id"])}</td><td>{E(b["title"])}</td><td>{pill(a["severity"])} → {pill(b["severity"])}</td></tr>' for a, b in c["changed"]], ["ID", "Finding", "Change"])
    return out

# ------------------------------------------------------------------ sections
def status_cell(f):
    st = f["status"]
    if st and is_uv(st): return f"<span class=uv>{E(st)}</span>"
    if st: return E(st)
    return "Open" if f["severity"] != "Info" else "Observation"

def card(f):
    st = f["status"]
    tag = (f'<span class="uvtag pot">Potential</span>' if f["basis"] == "inferred" else "") + (f'<span class="uvtag">{E(st)}</span>' if is_uv(st) else "")
    rows = []
    if f["basis"] == "inferred":
        bits = ["<b>Inferred</b> from a version string / fingerprint match, not observed directly. Treat as potential until confirmed."]
        if f["cve"]: bits.append("CVE: " + ", ".join(E(c) for c in f["cve"]))
        if f["claimed_severity"]: bits.append(f"Claimed severity {E(f['claimed_severity'])}, capped at {f['severity']}")
        if f["confidence"] is not None: bits.append(f"Confidence: {E(f['confidence'])}")
        rows.append(("Basis", " · ".join(bits)))
    elif f["confidence"] is not None:
        rows.append(("Basis", f"Observed · Confidence: {E(f['confidence'])}"))
    if f["description"]: rows.append(("Description", E(f["description"])))
    if f["evidence"]: rows.append(("Evidence", f'<pre class="ev">{E(f["evidence"])}</pre>'))
    if f["impact"]: rows.append(("Impact", E(f["impact"])))
    if f["remediation"]: rows.append(("Remediation", "<ol>" + "".join(f"<li>{E(x)}</li>" for x in f["remediation"]) + "</ol>"))
    body = "".join(f'<div class="row"><div class="lbl">{l}</div><div class="val">{v}</div></div>' for l, v in rows)
    return (f'<article class="card c-{f["severity"].lower()}"><header><div class="cid mono">{E(f["id"])}</div>'
            f'<h3>{E(f["title"])}</h3><div class="tags">{tag}{pill(f["severity"])}</div></header>'
            f'<div class="body">{body}</div></article>')

def potential(f):
    return '<span class="uvtag pot">Potential</span> ' if f["basis"] == "inferred" else ""

def short_action(f):
    if f.get("action"): return f["action"]
    if f["remediation"]:
        a = re.split(r"(?<=[.;:])\s", f["remediation"][0])[0].rstrip(".;:")
        return a if len(a) <= 60 else a[:57].rsplit(" ", 1)[0] + "…"
    return "Review and remediate"

def auto_verdict(d, grade, cnt, F):
    t = d["target"]; out = []
    worst = [s for s in SEV[:4] if cnt[s]]
    if not F:
        out.append(f"{E(t)} {OPENING[grade]}. No security findings were identified in the passive checks performed.")
    else:
        none_hi = [s.lower() for s in ("Critical", "High") if not cnt[s]]
        s1 = f"{E(t)} {OPENING[grade]}."
        if len(none_hi) == 2: s1 += " No critical or high-severity issues were found."
        elif cnt["Critical"] or cnt["High"]:
            parts = [f'{nw(cnt[s])} {s.lower()}' for s in ("Critical", "High") if cnt[s]]
            s1 += f" The assessment identified {join_and(parts)}-severity issue{'s' if cnt['Critical']+cnt['High']>1 else ''} that need prompt attention."
        if d["strengths"]:
            s1 += " Controls working well include " + join_and([E(s["title"]).lower() if s["title"][:2].upper()!=s["title"][:2] else E(s["title"]) for s in d["strengths"][:4]]) + "."
        out.append(s1)
        if worst:
            top = worst[0]; tf = [f for f in F if f["severity"] == top]
            names = join_and([E(f["title"]) for f in tf[:3]]) + (f" and {len(tf)-3} more" if len(tf) > 3 else "")
            s2 = f"The grade is driven mainly by {nw(len(tf))} {top.lower()}-severity finding{'s' if len(tf)>1 else ''}: {names}."
            lower = [s for s in worst[1:]]
            if lower: s2 += " There are also " + join_and([f"{nw(cnt[s])} {s.lower()}" for s in lower]) + "-severity item" + ("s" if sum(cnt[s] for s in lower) > 1 else "") + " to address."
            if grade != "A": s2 += f" <b>Resolving the {top.lower()}-severity finding{"s" if len(tf)>1 else ""} would raise the grade.</b>"
            out.append(s2)
        else:
            out.append("Only informational observations were recorded; no remediation is required.")
    return out

def appendix_html(d, letter="A"):
    parts = []
    for n, a in enumerate(d["appendix"], 1):
        typ = a.get("type", "raw"); c = a.get("content")
        cls = "sub app-h" + (" first" if n == 1 else "")
        if a.get("break") is False: cls = "sub"
        parts.append(f'<h3 class="{cls}">{letter}.{n} {E(a.get("title", ""))}</h3>')
        if a.get("note"): parts.append(f'<p class="muted" style="font-size:8pt">{E(a["note"])}</p>')
        if typ == "records":
            items = c.items() if isinstance(c, dict) else c
            parts.append('<table class="kv compact">' + "".join(f'<tr><th>{E(k)}</th><td class="mono">{E(v)}</td></tr>' for k, v in items) + "</table>")
        elif typ == "table":
            cols = c.get("columns", []); rows = c.get("rows", []); widths = c.get("widths")
            cg = "<colgroup>" + "".join(f'<col style="width:{w}">' if w else "<col>" for w in widths) + "</colgroup>" if widths else ""
            def cell(v):
                if isinstance(v, list): v = "\n".join(map(str, v))
                v = E(v).replace("\n", "<br>")
                return f'<td class="mono wrap">{v}</td>'
            parts.append(f'<table class="raw">{cg}<thead><tr>' + "".join(f"<th>{E(x)}</th>" for x in cols) +
                         "</tr></thead><tbody>" + "".join("<tr>" + "".join(cell(v) for v in r) + "</tr>" for r in rows) + "</tbody></table>")
        else:
            if not isinstance(c, str): c = json.dumps(c, indent=1)
            parts.append(f'<pre class="json">{E(c)}</pre>')
    return "".join(parts)

def build(d):
    F = d["findings"]; cnt = Counter(f["severity"] for f in F)
    computed, score = compute_grade(cnt)
    grade = (d.get("grade") or computed).strip().upper()[:1]
    tagline = d.get("tagline") or TAGLINE[grade]
    b = d.get("_brand") or load_brand(d)
    t = d["target"]; date = d["date"]; prep = d.get("prepared_by", b["name"])
    auth = d.get("authorized_by", "Not stated")
    ex = bool(d.get("example"))

    css = open(os.path.join(HERE, "style.css")).read()
    css = (css.replace("__TARGET__", css_str(t)).replace("__BRAND_VARS__", brand_vars(b))
              .replace("__HEADER_LEFT__", css_str(f"{b['name']}  |  Passive Security Assessment"))
              .replace("__FOOTER_LEFT__", "CONFIDENTIAL")
              .replace("__POWERED__", css_str(b["powered_by"]["text"]) if b["powered_by"] else ""))
    for k, f in (("__INTER__", "build/inter.woff"), ("__MONO__", "build/mono.woff"),
                 ("__SERIFI__", "build/newsreader-italic.woff2"), ("__SERIF__", "build/newsreader.woff2")):
        css = css.replace(k, font_b64(f))
    if ex: css = css.replace('content:"CONFIDENTIAL"', 'content:"EXAMPLE DATA"')

    # numbering of optional sections
    ch = d.get("_changes")
    secs = ["exec", "scope", "summary"] + (["changes"] if ch else []) + ["findings"]
    if d["strengths"]: secs.append("strengths")
    has_lim = bool(d["unverified"] or d.get("limitations") or d["check_log"])
    if has_lim: secs.append("limits")
    num = {s: f"{i+1:02d}" for i, s in enumerate(secs)}

    counts = "".join(f'<div class="sc s-{s.lower()}{" zero" if cnt[s]==0 else ""}"><div class="n">{cnt[s]}</div><div class="l">{s}</div></div>' for s in SEV)
    scale = "".join(f'<span class="{"on" if g==grade else ""}">{g}</span>' for g in "ABCDF")

    actionable = [f for f in F if f["severity"] != "Info"]
    prio_html = ""
    if actionable:
        top = actionable[0]["severity"]
        pf = [f for f in actionable if f["severity"] == top][:3]
        if len(pf) < 3: pf += [f for f in actionable if f not in pf][:3 - len(pf)]
        prio_html = ('<div class="priorities"><div class="ph">Priority actions</div><ol>' +
                     "".join(f'<li><span class="mono">{E(f["id"])}</span><span>{E(f["title"])}</span><span class="act">{E(short_action(f))} →</span></li>' for f in pf) +
                     "</ol></div>")
    else:
        prio_html = '<div class="priorities"><div class="ph">Priority actions</div><div style="padding:3mm 4.5mm">No remediation is required. Re-run this check periodically or after significant changes.</div></div>'

    note = ""
    if d["unverified"]:
        items = join_and([E(u["item"]) for u in d["unverified"][:3]]) + (f" and {len(d['unverified'])-3} more" if len(d["unverified"]) > 3 else "")
        n = len(d["unverified"])
        note = f'<div class="note">{nw(n).capitalize()} item{"s" if n>1 else ""} could not be verified from the scanning host: {items}. See Section {num["limits"]}.</div>'

    badc = [c for c in d["check_log"] if c["status"] != "ok"]
    if badc:
        txt = f'{nw(len(badc)).capitalize()} check{"s" if len(badc)>1 else ""} failed or {"were" if len(badc)>1 else "was"} skipped ({join_and([E(c["check"]) for c in badc[:3]])}{" and more" if len(badc)>3 else ""}); see Assessment coverage in Section {num["limits"]}.'
        note = note.replace("</div>", " " + txt + "</div>") if note else f'<div class="note">{txt}</div>'
    verdict = d.get("summary")
    verdict_paras = [E(p) for p in as_list(verdict)] if verdict else auto_verdict(d, grade, cnt, F)
    verdict_html = "".join(f'<p class="lead">{p}</p>' for p in verdict_paras)
    grade_note = f"Computed from findings (score {score}/100)" if not d.get("grade") else f"Assessor-assigned grade (rubric: {computed})"

    scope = d.get("scope", t)
    scope_rows = [("Target", scope if isinstance(scope, str) else ", ".join(scope)),
                  ("Assessment type", d.get("assessment_type", "Passive, external, non-intrusive reconnaissance")),
                  ("Assessment date", f"{date} (America/Vancouver, PT)"),
                  ("Authorization", auth), ("Prepared by", prep),
                  ("Time zone", "All times converted to America/Vancouver (PT)")]
    methods = as_list(d.get("methods")) or ["Passive DNS, registry and Certificate Transparency lookups", "Ordinary requests to public pages"]
    oos = as_list(d.get("out_of_scope")) or ["Brute force of any kind", "Port scanning", "Exploitation or intrusive testing", "Authenticated testing"]

    rows = "".join(f'<tr><td class="mono id">{E(f["id"])}</td><td>{potential(f)}{E(f["title"])}</td><td>{pill(f["severity"])}</td><td class="st">{status_cell(f)}</td></tr>' for f in F)
    summary_body = (f'<table class="ft"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>'
                    if F else '<div class="empty">No findings were recorded for this target.</div>')
    groups = ""
    for s in SEV:
        sub = [f for f in F if f["severity"] == s]
        if not sub: continue
        groups += (f'<div class="keep"><div class="group-h">{s} severity · {len(sub)}</div>{card(sub[0])}</div>'
                   + "\n".join(card(f) for f in sub[1:]))
    if not F: groups = '<div class="empty">No findings to detail. The passive checks performed did not identify any issues.</div>'

    strengths_sec = ""
    if d["strengths"]:
        sh = "".join(f'<div class="str"><div class="tick">✓</div><div><b>{E(s.get("title"))}</b>{detail(s)}</div></div>' for s in d["strengths"])
        strengths_sec = f'''<section id="strengths"><div class="sec-head"><span class="num">{num["strengths"]}</span><h2>Strengths</h2></div>
 <p class="lead" style="margin-bottom:6mm">The following controls were observed working as intended and should be kept in place.</p><div class="strs">{sh}</div></section>'''

    lim_sec = ""
    if has_lim:
        lh = ""
        for u in d["unverified"]:
            lh += (f'<div class="lim"><div class="t"><span class="uv">Unverified</span><b>{E(u["item"])}</b></div>'
                   + (f'<p>{E(u.get("reason"))}</p>' if u.get("reason") else "")
                   + (f'<p><b>To confirm:</b> {E(u["confirm"])}</p>' if u.get("confirm") else "") + "</div>")
        gl = as_list(d.get("limitations"))
        if gl:
            lh += ('<h3 class="sub">General limitations</h3>' if d["unverified"] else "") + '<div class="box"><ul>' + "".join(f"<li>{E(x)}</li>" for x in gl) + "</ul></div>"
        if d["check_log"]:
            order = {"failed": 0, "skipped": 1, "ok": 2}
            cl = sorted(d["check_log"], key=lambda c: order[c["status"]])
            bad = [c for c in cl if c["status"] != "ok"]
            lbl = {"ok": '<span class="ok">OK</span>', "failed": '<span class="uv fail">Failed</span>', "skipped": '<span class="uv">Skipped</span>'}
            lh += (f'<h3 class="sub">Assessment coverage</h3><p style="font-size:8.6pt;color:var(--slate)">{len(cl)} checks run: '
                   f'{sum(c["status"]=="ok" for c in cl)} completed, {sum(c["status"]=="failed" for c in cl)} failed, {sum(c["status"]=="skipped" for c in cl)} skipped.'
                   + (" Failed and skipped checks are listed first; their results are not reflected in the findings." if bad else "") + '</p>'
                   '<table class="ft cov"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>'
                   + "".join(f'<tr><td>{E(c["check"])}</td><td class="st">{lbl[c["status"]]}</td><td>{E(c.get("detail",""))}</td></tr>' for c in cl)
                   + "</tbody></table>")
        lim_sec = f'<section id="limits"><div class="sec-head"><span class="num">{num["limits"]}</span><h2>{"Unverified Items &amp; Limitations" if d["unverified"] else "Limitations &amp; Coverage"}</h2></div>{lh}</section>'

    app_sec = ""
    if d["appendix"]:
        app_sec = f'<section id="appendix"><div class="sec-head"><span class="num">A</span><h2>Appendix: Raw Records</h2></div>{appendix_html(d)}<div class="end">End of report · {E(prep)} · Generated by Grok Bot{(" · " + powered_html(b, "x").replace("<div class=\"x\">", "").replace("</div>", "")) if b["powered_by"] else ""}</div></section>'
    end_inline = "" if d["appendix"] else f'<div class="end">End of report · {E(prep)} · Generated by Grok Bot{(" · " + powered_html(b, "x").replace("<div class=\"x\">", "").replace("</div>", "")) if b["powered_by"] else ""}</div>'
    # attach end marker to the last section present
    last_extra = end_inline

    sfoot = f'<div class="sfoot"><span>{E(b["name"])} · {E(t)}</span>{powered_html(b, "x")}</div>' if b["powered_by"] else ""
    conf = (f"This report contains security information about {E(t)} and is intended solely for the domain owner. Do not distribute it without the owner's permission. "
            "Findings reflect what could be observed passively on the assessment date and may change over time.")
    if ex: conf = f"<b>EXAMPLE DATA</b>This is a hypothetical sample report. {E(t)} and every finding in it are fictional and exist only to demonstrate the report format."
    else: conf = "<b>CONFIDENTIAL</b>" + conf

    tail_sections = strengths_sec + lim_sec
    if last_extra:
        if tail_sections: tail_sections = tail_sections[:tail_sections.rindex("</section>")] + last_extra + "</section>"
        else: groups += last_extra

    return grade, cnt, f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Passive Security Assessment · {E(t)} · {E(prep)}</title><style>{css}</style></head><body>
<div class="cover"><div class="band"></div><div class="grid"></div>{'<div class="example-flag">EXAMPLE DATA</div>' if ex else ''}<div class="in">
 {brand_mark(b)}
 <div class="kicker">Passive Assessment</div>
 <h1>External Security<br><em>Reconnaissance Report</em></h1>
 <div class="target">{E(t)}</div>
 <div class="rule"></div>
 <div class="meta">
  <div><span>Assessment date</span><b>{E(nice_date(date))} (PT)</b></div>
  <div><span>Assessment type</span><b>Passive, non-intrusive</b></div>
  <div><span>Prepared by</span><b>{E(prep)}</b></div>
  <div><span>Authorization</span><b>{E(auth)}</b></div>
  <div><span>Overall grade</span><b>{grade} <i class="gtag">· {E(tagline)}</i></b></div>
  <div><span>Version</span><b>{E(d.get("version","1.0"))}</b></div>
 </div>
 <div class="conf">{conf}{powered_html(b, "pby-c")}</div>
</div></div>
<section id="exec">
 {'<div class="banner-ex">EXAMPLE DATA · HYPOTHETICAL TARGET AND FINDINGS</div>' if ex else ''}
 <div class="sec-head"><span class="num">{num["exec"]}</span><h2>Executive Summary</h2></div>
 <div class="exec">
  <div class="grade"><div class="cap">Overall grade</div><div class="letter">{grade}</div><div class="scale">{scale}</div><div class="sub2">{E(tagline)}</div></div>
  <div class="verdict"><h3>Verdict</h3>{verdict_html}<p class="muted" style="font-size:7.8pt;margin:0">{E(grade_note)}</p></div>
 </div>
 <div class="counts">{counts}</div>
 {prio_html}
 {note}
</section>
<section id="scope">
 <div class="sec-head"><span class="num">{num["scope"]}</span><h2>Scope &amp; Methodology</h2></div>
 <table class="kv">{"".join(f"<tr><th>{k}</th><td>{E(v)}</td></tr>" for k, v in scope_rows)}</table>
 <div class="cols2">
  <div class="box"><h4>Sources &amp; techniques</h4><ul>{"".join(f"<li>{E(m)}</li>" for m in methods)}</ul></div>
  <div class="box"><h4>Out of scope</h4><ul>{"".join(f"<li>{E(m)}</li>" for m in oos)}</ul>
   <p class="muted" style="margin:3mm 0 0;font-size:8.3pt">Items marked <span class="uv">Unverified</span> could not be observed from the scanning host.</p></div>
 </div>
 <h3 class="sub">Severity ratings</h3>
 <table class="legend">
  <tr><td>{pill("Critical")}</td><td>Directly exploitable weakness with serious impact; fix immediately.</td></tr>
  <tr><td>{pill("High")}</td><td>Significant weakness likely to be exploitable; fix as a priority.</td></tr>
  <tr><td>{pill("Medium")}</td><td>Missing control that meaningfully reduces defence in depth; plan a fix.</td></tr>
  <tr><td>{pill("Low")}</td><td>Hardening opportunity with limited direct risk.</td></tr>
  <tr><td>{pill("Info")}</td><td>Observation or context; no direct risk identified.</td></tr>
 </table>
 <div class="keep"><h3 class="sub">Grading</h3>
 <p style="font-size:8.6pt;color:var(--slate)">Score = 100 − (40 × critical + 15 × high + 5 × medium + 1 × low). A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F. Caps: any high → at best C; one critical → at best D; two or more critical → F.</p></div>
</section>
<section id="summary"><div class="sec-head"><span class="num">{num["summary"]}</span><h2>Findings Summary</h2></div>{summary_body}</section>
{f'<section id="changes"><div class="sec-head"><span class="num">{num["changes"]}</span><h2>Changes Since Last Assessment</h2></div>{changes_html(ch)}</section>' if ch else ""}
<section id="findings"><div class="sec-head"><span class="num">{num["findings"]}</span><h2>Detailed Findings</h2></div>{groups}</section>
{tail_sections}
{app_sec}
</body></html>'''.replace("</section>", sfoot + "</section>")

def find_chrome():
    for c in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        p = shutil.which(c)
        if p: return p
    sys.exit("error: no Chromium/Chrome found for PDF rendering")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings"); ap.add_argument("--out", required=True)
    ap.add_argument("--no-pdf", action="store_true", help="write HTML only")
    ap.add_argument("--history-dir", help="snapshot folder (default $SCAFU_REPORTS_DIR/<target>/history/, where SCAFU_REPORTS_DIR defaults to ./reports next to gen.py)")
    ap.add_argument("--no-history", action="store_true", help="neither read nor save snapshots")
    ap.add_argument("--auto-cap", action="store_true", help="downgrade inferred critical/high findings to medium instead of failing")
    a = ap.parse_args()
    return run(a.findings, a.out, pdf=not a.no_pdf, history_dir=a.history_dir, history=not a.no_history, cap=a.auto_cap)

def run(findings, out, pdf=True, history_dir=None, history=True, cap=False):
    try:
        raw = json.load(open(findings))
    except Exception as x:
        print(f"error: cannot read {findings}: {x}", file=sys.stderr); sys.exit(1)
    try:
        d = normalize(raw, cap=cap)
    except ValidationError as x:
        for line in str(x).splitlines(): print("error:", line, file=sys.stderr)
        sys.exit(1)
    try:
        d["_brand"] = load_brand(raw, base_dir=os.path.dirname(os.path.abspath(findings)))
    except (ValidationError, KeyError, OSError) as x:
        for line in str(x).splitlines(): print("error:", line, file=sys.stderr)
        sys.exit(1)
    hdir = None
    if history:
        hdir = history_dir or os.path.join(os.environ.get("SCAFU_REPORTS_DIR") or os.path.join(HERE, "reports"), re.sub(r"[^A-Za-z0-9._-]", "_", d["target"]), "history")
        prev = latest_snapshot(hdir)
        if prev:
            try: d["_changes"] = diff(json.load(open(prev)), d)
            except (ValidationError, ValueError) as x: print(f"warning: ignoring unreadable snapshot {prev}: {x}", file=sys.stderr)
    grade, cnt, doc = build(d)
    a = argparse.Namespace(out=out, no_pdf=not pdf)
    os.makedirs(a.out, exist_ok=True)
    out = os.path.abspath(a.out); h = os.path.join(out, "report.html"); p = os.path.join(out, "report.pdf")
    open(h, "w").write(doc)
    if not a.no_pdf:
        subprocess.run([find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={p}", "file://" + h], check=True, capture_output=True, timeout=180)
        subprocess.run(["pdftoppm", "-png", "-r", "90", "-f", "1", "-l", "2", p, os.path.join(out, "preview")], check=True)
        for f in os.listdir(out):
            m = re.fullmatch(r"preview-0*(\d+)\.png", f)
            if m: os.replace(os.path.join(out, f), os.path.join(out, f"preview-{m.group(1)}.png"))
        pages = subprocess.run(["pdfinfo", p], capture_output=True, text=True).stdout
        pages = re.search(r"Pages:\s+(\d+)", pages).group(1) if "Pages" in pages else "?"
    else: pages = "-"
    snap = save_snapshot(auto_cap(copy.deepcopy(raw)) if cap else raw, hdir, grade) if history else None
    print(f"grade {grade} | " + " ".join(f"{s}:{cnt[s]}" for s in SEV) + f" | pages {pages} | {out}"
          + (f" | changes vs {d['_changes']['prev_date']}" if d.get("_changes") else "") + (f" | snapshot {snap}" if snap else ""))
    return out

if __name__ == "__main__":
    main()
