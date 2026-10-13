import json, os, subprocess, sys, shutil, re
from collections import Counter
import pytest
import gen, validate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, "gen.py")

def F(sev="low", title=None, **kw):
    F.n = getattr(F, "n", 0) + 1
    return dict(severity=sev, title=title or f"Finding {F.n}", **kw)

def full_log():
    return [{"id": c, "check": n, "status": "ok", "detail": "fixture"} for c, n in validate.required_checks()]

def doc(findings=(), **kw):
    d = dict(target="t.test", date="2026-10-12", findings=list(findings), check_log=full_log()); d.update(kw); return d

def render(d, allow_incomplete=False):
    _, _, html = gen.build(gen.normalize(d, allow_incomplete=allow_incomplete)); return html

def cli(tmp_path, d, *args):
    p = tmp_path / "in.json"; p.write_text(json.dumps(d))
    return subprocess.run([sys.executable, GEN, str(p), "--out", str(tmp_path / "out"), *args], capture_output=True, text=True)

# ---------------------------------------------------------------- schema rejections
@pytest.mark.parametrize("d,msg", [
    ({"findings": []}, "target"),
    (doc(date="12/10/2026"), "date"),
    (doc(bogus=1), "unknown field 'bogus'"),
    (doc([F("severe")]), "severity"),
    (doc([{"severity": "low"}]), "title"),
    (doc([F(basis="guessed")]), "basis"),
    (doc([F(confidence="very")]), "confidence"),
    (doc([F(confidence=1.5)]), "confidence"),
    (doc([F(title="Same"), F(title="same")]), "duplicate key"),
    (doc([F(id="L-01"), F(id="L-01")]), "duplicate 'L-01'"),
    (doc([F("high", basis="inferred")]), "inferred"),
    (doc([F("critical", basis="inferred", claimed_severity="critical")]), "inferred"),
    (doc([F(cve="CVE-2021-1")]), "basis=inferred"),
    (doc(check_log=[{"check": "x", "status": "broken"}]), "check_log"),
    (doc(appendix=[{"title": "x", "type": "chart", "content": 1}]), "appendix"),
    (doc(appendix=[{"title": "x", "type": "table", "content": {"rows": []}}]), "table"),
    (doc(grade="Z"), "grade"),
    (doc(findings="nope"), "findings"),
])
def test_rejections(d, msg):
    errs = validate.validate(d)
    assert errs and any(msg in e for e in errs), errs
    with pytest.raises(gen.ValidationError): gen.normalize(d)

def test_examples_valid():
    for f in os.listdir(os.path.join(ROOT, "examples")):
        assert validate.validate(json.load(open(os.path.join(ROOT, "examples", f)))) == [], f

def test_cli_exits_nonzero_on_invalid(tmp_path):
    r = cli(tmp_path, doc([F("high", basis="inferred")]), "--no-pdf", "--no-history")
    assert r.returncode == 1 and "error:" in r.stderr and not (tmp_path / "out" / "report.html").exists()
    r = subprocess.run([sys.executable, os.path.join(ROOT, "validate.py"), str(tmp_path / "in.json")], capture_output=True, text=True)
    assert r.returncode == 1

# ---------------------------------------------------------------- rubric
def g(**c): return gen.compute_grade(Counter(c))
@pytest.mark.parametrize("c,grade,score", [
    ({}, "A", 100), ({"Low": 10}, "A", 90), ({"Low": 11}, "B", 89), ({"Medium": 2}, "A", 90),
    ({"Medium": 3, "Low": 7, "Info": 6}, "B", 78), ({"Medium": 5}, "B", 75), ({"Medium": 6}, "C", 70),
    ({"Medium": 8}, "C", 60), ({"Medium": 9}, "D", 55), ({"Medium": 12}, "D", 40), ({"Medium": 13}, "F", 35),
    ({"Info": 500}, "A", 100),
    ({"High": 1}, "C", 85),            # capped at C
    ({"High": 2, "Medium": 3}, "D", 55),
    ({"Critical": 1}, "D", 60),        # capped at D
    ({"Critical": 2}, "F", 20),        # 2+ critical -> F
    ({"Critical": 1, "High": 2, "Medium": 2, "Low": 1}, "F", 19),
])
def test_rubric(c, grade, score):
    assert g(**c) == (grade, score)

def test_grade_override_and_computed_note():
    h = render(doc([F("high")], grade="b"))
    assert '<div class="letter">B</div>' in h and "rubric: C" in h
    assert '<div class="letter">C</div>' in render(doc([F("high")]))

# ---------------------------------------------------------------- id numbering
def test_id_numbering():
    d = gen.normalize(doc([F("low", "a"), F("high", "b"), F("low", "c", id="L-01"), F("info", "d"), F("low", "e"), F("critical", "f")]))
    assert [(f["id"], f["title"]) for f in d["findings"]] == [
        ("C-01", "f"), ("H-01", "b"), ("L-02", "a"), ("L-01", "c"), ("L-03", "e"), ("I-01", "d")]

def test_key_default_slug():
    d = gen.normalize(doc([F(title="No HSTS (Strict-Transport-Security) header!"), F(title="x", key="custom")]))
    assert [f["key"] for f in d["findings"]] == ["no-hsts-strict-transport-security-header", "custom"]

# ---------------------------------------------------------------- inferred cap
def test_inferred_label_and_status():
    d = doc([F("medium", "nginx CVE", basis="inferred", claimed_severity="critical", confidence="low", cve=["CVE-2021-23017"])])
    n = gen.normalize(d)["findings"][0]
    assert n["severity"] == "Medium" and n["claimed_severity"] == "Critical" and n["status"] == "Unverified"
    h = render(d)
    summary = h.split('id="summary"')[1].split("</section>")[0]
    assert "Potential</span>" in summary and "<span class=uv>Unverified</span>" in summary
    card = h.split('<article')[1]
    assert "Potential</span>" in card and "Claimed severity Critical, capped at Medium" in card and "CVE-2021-23017" in card

def test_auto_cap(tmp_path):
    d = doc([F("critical", "x", basis="inferred")])
    n = gen.normalize(d, cap=True)["findings"][0]
    assert (n["severity"], n["claimed_severity"]) == ("Medium", "Critical")
    r = cli(tmp_path, d, "--no-pdf", "--no-history", "--auto-cap")
    assert r.returncode == 0, r.stderr

def test_inferred_defensive_cap_in_normalizer():
    # bypass validation to prove rendering itself never shows inferred findings above medium
    orig = validate.validate
    validate.validate = lambda d, **k: []
    try: n = gen.normalize(doc([F("high", "x", basis="inferred")]))["findings"][0]
    finally: validate.validate = orig
    assert n["severity"] == "Medium" and n["claimed_severity"] == "High"

# ---------------------------------------------------------------- sections adapt
def test_empty_sections_omitted():
    h = render(doc([F("low")], check_log=[]), allow_incomplete=True)
    for sid in ("strengths", "limits", "appendix", "changes"): assert f'id="{sid}"' not in h
    assert "High severity" not in h and "Low severity · 1" in h
    for s in gen.SEV: assert f'<div class="l">{s}</div>' in h      # all 5 count cards

def test_sections_present_and_numbered():
    h = render(doc([F("low")], strengths=["s"], unverified=[{"item": "u", "reason": "r"}],
                   check_log=[{"check": "Port 80", "status": "failed", "detail": "blocked"}, {"check": "DNS", "status": "ok"}],
                   appendix=[{"title": "raw", "type": "raw", "content": "x"}]), allow_incomplete=True)
    assert '<span class="num">05</span><h2>Strengths' in h and '<span class="num">06</span><h2>Unverified' in h
    lim = h.split('id="limits"')[1]
    assert "Assessment coverage" in lim and lim.index("Port 80") < lim.index("DNS") and "Failed</span>" in lim
    assert "failed or was skipped (Port 80)" in h

def test_check_log_only_creates_limits():
    h = render(doc([], check_log=[{"check": "TLS 1.0", "status": "skipped", "detail": "untestable"}]), allow_incomplete=True)
    assert 'id="limits"' in h and "Limitations &amp; Coverage" in h and "Skipped</span>" in h

def test_priorities():
    h = render(doc([F("medium", "m1"), F("low", "l1"), F("high", "h1"), F("info", "i1")]))
    pr = h.split('class="priorities"')[1].split("</ol>")[0]
    assert re.findall(r'class="mono">(\w-\d+)<', pr) == ["H-01", "M-01", "L-01"]

# ---------------------------------------------------------------- volume
def test_zero_findings_render(tmp_path):
    r = cli(tmp_path, doc([]), "--no-pdf", "--no-history"); assert r.returncode == 0, r.stderr
    h = (tmp_path / "out" / "report.html").read_text()
    assert "No findings were recorded" in h and '<div class="letter">A</div>' in h

def test_45_findings_render(tmp_path):
    sev = ["critical", "high", "medium", "low", "info"]
    fs = [F(sev[i % 5], f"Stress {i}", evidence="y" * (i * 40)) for i in range(45)]
    r = cli(tmp_path, doc(fs), "--no-pdf", "--no-history"); assert r.returncode == 0, r.stderr
    h = (tmp_path / "out" / "report.html").read_text()
    assert h.count("<article") == 45 and "C-09" in h and "I-09" in h

@pytest.mark.skipif(not shutil.which("pdftoppm") or not any(shutil.which(c) for c in ("chromium", "google-chrome", "chromium-browser")), reason="no chrome/poppler")
def test_pdf_smoke(tmp_path):
    r = cli(tmp_path, json.load(open(os.path.join(ROOT, "examples", "hypothetical-critical.json"))), "--history-dir", str(tmp_path / "h"))
    assert r.returncode == 0, r.stderr
    out = tmp_path / "out"
    for f in ("report.html", "report.pdf", "preview-1.png", "preview-2.png"): assert (out / f).stat().st_size > 1000, f
    assert (out / "report.pdf").read_bytes()[:5] == b"%PDF-"

# ---------------------------------------------------------------- history
def test_history(tmp_path):
    h = tmp_path / "hist"
    v1 = doc([F("high", "Exposed git"), F("medium", "No HSTS"), F("low", "Cert expiring")])
    r = cli(tmp_path, v1, "--no-pdf", "--history-dir", str(h)); assert r.returncode == 0, r.stderr
    snaps = os.listdir(h); assert len(snaps) == 1 and re.fullmatch(r"2026-10-12_\d{6}\.json", snaps[0])
    s = json.load(open(h / snaps[0])); assert s["_snapshot"]["grade"] == "C" and len(s["findings"]) == 3
    assert 'id="changes"' not in (tmp_path / "out" / "report.html").read_text()   # first run: no section

    v2 = doc([F("medium", "No HSTS"), F("high", "Cert expiring"), F("low", "No CAA")], date="2026-11-12")
    r = cli(tmp_path, v2, "--no-pdf", "--history-dir", str(h)); assert r.returncode == 0, r.stderr
    assert len(os.listdir(h)) == 2
    html = (tmp_path / "out" / "report.html").read_text()
    ch = html.split('id="changes"')[1].split("</section>")[0]
    assert "2026-10-12" in ch and "has unchanged" in ch and "<b>C → C</b>" in ch
    assert "New findings" in ch and "No CAA" in ch
    assert "Resolved since last assessment" in ch and "Exposed git" in ch
    assert "Severity changed" in ch and "Cert expiring" in ch
    assert "1 new, 1 resolved, 1 with changed severity, 1 unchanged" in ch

def test_diff_grade_delta():
    prev = doc([F("critical", "a")]); cur = gen.normalize(doc([F("low", "b")]))
    c = gen.diff(prev, cur)
    assert (c["prev_grade"], c["grade"], c["grade_delta"]) == ("D", "A", 3)
    assert [f["title"] for f in c["new"]] == ["b"] and [f["title"] for f in c["resolved"]] == ["a"]

def test_key_matching_survives_title_change():
    prev = doc([F("high", "Old wording", key="git")]); cur = gen.normalize(doc([F("medium", "New wording", key="git")]))
    c = gen.diff(prev, cur)
    assert not c["new"] and not c["resolved"] and len(c["changed"]) == 1

def test_no_history_flag(tmp_path):
    r = cli(tmp_path, doc([]), "--no-pdf", "--no-history", "--history-dir", str(tmp_path / "h"))
    assert r.returncode == 0 and not (tmp_path / "h").exists()

def test_default_history_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("SCAFU_REPORTS_DIR", raising=False)
    seen = {}
    monkeypatch.setattr(gen, "save_snapshot", lambda raw, hdir, grade: seen.setdefault("d", hdir))
    monkeypatch.setattr(gen, "latest_snapshot", lambda hdir: None)
    p = tmp_path / "in.json"; p.write_text(json.dumps(doc([])))
    gen.run(str(p), str(tmp_path / "o"), pdf=False)
    assert seen["d"] == os.path.join(ROOT, "reports", "t.test", "history")
    monkeypatch.setenv("SCAFU_REPORTS_DIR", str(tmp_path / "r")); seen.clear()
    gen.run(str(p), str(tmp_path / "o"), pdf=False)
    assert seen["d"] == str(tmp_path / "r" / "t.test" / "history")

# ---------------------------------------------------------------- branding
def test_powered_by_line_default_scafu():
    h = render(doc([F("low")]))
    link = '<a href="https://sca-fu.com">Powered by SCAFU · sca-fu.com</a>'
    cover = h.split('<div class="cover">')[1].split("<section")[0]
    assert link in cover                                              # cover, linked
    assert '@bottom-center{content:"Powered by SCAFU · sca-fu.com"' in h   # every PDF page footer
    assert h.count('<div class="sfoot">') == h.count("</section>") >= 4 and h.count(link) >= h.count("</section>") + 1  # every screen page footer + end line
    assert "SCAFU  |  Passive Security Assessment" in h and '<span class="wm">SCAF<b>U</b></span>' in h

def test_no_external_loads():
    h = render(doc([F("low")], appendix=[{"title": "x", "type": "raw", "content": "y"}]))
    assert not re.search(r'(src|href)="https?://(?!sca-fu\.com)', h)
    assert not re.search(r"url\((?!data:)", h) and "@import" not in h and "<script" not in h
    assert h.count("@font-face") == 4

def test_brand_override_and_disable_powered_by(tmp_path):
    logo = tmp_path / "logo.svg"; logo.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>')
    d = doc([F("low")], brand={"name": "Acme Sec", "url": "https://acme.test", "logo": str(logo), "powered_by": False,
                               "colors": {"dark": "#101820", "accent": "#88aacc"}})
    n = gen.normalize(d); n["_brand"] = gen.load_brand(d)
    _, _, h = gen.build(n)
    assert "Powered by" not in h and "Acme Sec  |  Passive" in h and "--navy:#101820" in h and "--brand-accent:#88aacc" in h
    assert 'src="data:image/svg+xml;base64,' in h and "--on-dark:#f3ede4" in h    # unspecified colours fall back to SCAFU

@pytest.mark.parametrize("brand,msg", [
    ({"colors": {"dark": "navy"}}, "colors.dark"), ({"url": "sca-fu.com"}, "url"), ({"logo": "https://x.test/l.png"}, "logo"),
    ({"powered_by": {"url": "ftp://x"}}, "powered_by"), ({"powered_by": 5}, "powered_by"), ({"font": "x"}, "unknown field"),
])
def test_brand_rejections(brand, msg):
    errs = validate.validate(doc(brand=brand))
    assert any(msg in e for e in errs), errs


# ---------------------------------------------------------------- required-coverage gate
def test_checks_json_canonical_list():
    assert [c for c, _ in validate.required_checks()] == ["dns_records", "caa", "spf", "dkim", "dmarc", "mta_sts_tlsrpt", "dnssec", "tls_cert",
        "tls_versions", "ct_subdomains", "http_headers", "https_redirect", "robots_security_txt", "rdap", "fingerprint"]

def test_gate_missing_check_fails():
    d = doc([]); d["check_log"] = [c for c in d["check_log"] if c["id"] != "dnssec"]
    errs = validate.validate(d)
    assert any("'dnssec'" in e and "missing" in e for e in errs)
    assert validate.validate(d, allow_incomplete=True) == []
    with pytest.raises(gen.ValidationError): gen.normalize(d)

def test_gate_failed_or_skipped_needs_detail():
    d = doc([]); d["check_log"][0].update(status="failed", detail="DoH timeout"); d["check_log"][1].update(status="skipped", detail="n/a")
    assert validate.validate(d) == []
    d["check_log"][2].update(status="skipped", detail="  ")
    assert any("'spf' is skipped without a detail" in e for e in validate.validate(d))

def test_gate_cli_and_banner(tmp_path):
    d = doc([F("low")], check_log=[])
    r = cli(tmp_path, d, "--no-pdf", "--no-history"); assert r.returncode == 1 and "coverage:" in r.stderr
    r = subprocess.run([sys.executable, os.path.join(ROOT, "validate.py"), str(tmp_path / "in.json")], capture_output=True, text=True); assert r.returncode == 1
    r = subprocess.run([sys.executable, os.path.join(ROOT, "validate.py"), str(tmp_path / "in.json"), "--allow-incomplete"], capture_output=True, text=True)
    assert r.returncode == 0 and "INCOMPLETE" in r.stdout
    r = cli(tmp_path, d, "--no-pdf", "--no-history", "--allow-incomplete"); assert r.returncode == 0, r.stderr
    h = (tmp_path / "out" / "report.html").read_text()
    assert "INCOMPLETE ASSESSMENT</b> · 15 required checks" in h and 'example-flag inc' in h

def test_complete_report_has_no_banner():
    assert "INCOMPLETE ASSESSMENT" not in render(doc([F("low")]))
