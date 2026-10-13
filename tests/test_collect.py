"""Collector rule tests on fixture raw data (no network), plus an optional live smoke test."""
import datetime as dt, json, os, socket, subprocess, sys, urllib.request
import pytest
import collect, validate, gen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FX = os.path.join(ROOT, "tests", "fixtures")
NOW = dt.datetime(2026, 10, 12, 12, 0, tzinfo=dt.timezone.utc)
raw = lambda n: json.load(open(os.path.join(FX, f"raw_{n}.json")))

def run(r):
    log, F, S, U = collect.analyze(r, NOW)
    return {c["id"]: c for c in log}, {f["key"]: f for f in F}, [s["title"] for s in S], U

def test_good_domain_has_no_findings_beyond_info():
    log, F, S, U = run(raw("good"))
    assert set(log) == {c for c, _ in validate.required_checks()} and all(c["status"] == "ok" for c in log.values())
    assert {k for k, f in F.items() if f["severity"] != "info"} == set(), F
    for s in ("HSTS", "Content-Security-Policy", "DNSSEC", "CAA records", "SPF hard fail", "DMARC reject", "MTA-STS and TLS-RPT",
              "security.txt", "Modern TLS only", "Valid TLS certificate", "HTTPS redirect", "Registrar transfer lock", "DKIM published"):
        assert s in S, s

@pytest.mark.parametrize("key,sev", [
    ("spf-plus-all", "high"), ("no-caa", "low"), ("dmarc-none", "medium"), ("no-mta-sts-tlsrpt", "low"), ("no-dnssec", "medium"),
    ("cert-expiring", "medium"), ("weak-tls", "medium"), ("missing-hsts", "medium"), ("csp-unsafe", "medium"), ("acao-wildcard", "low"),
    ("no-https-redirect", "medium"), ("no-security-txt", "low"), ("version-disclosure", "low"), ("robots-sensitive", "info"), ("fingerprint", "info"),
])
def test_bad_domain_rules(key, sev):
    _, F, _, _ = run(raw("bad"))
    assert key in F and F[key]["severity"] == sev, sorted((k, f["severity"]) for k, f in F.items())

def test_bad_domain_strengths_and_titles():
    _, F, S, _ = run(raw("bad"))
    assert "HSTS" not in S and "DNSSEC" not in S and "Registrar transfer lock" not in S
    assert "'unsafe-inline' and 'unsafe-eval'" in F["csp-unsafe"]["title"] and "TLSv1.0" in F["weak-tls"]["title"]
    assert "expires in 9 day" in F["cert-expiring"]["title"]

@pytest.mark.parametrize("mutate,key,sev", [
    (lambda r: r["dns"]["TXT"].update(answers=["v=spf1 mx ~all"]), "spf-softfail", "low"),
    (lambda r: r["dns"]["TXT"].update(answers=["v=spf1 mx ?all"]), "spf-neutral", "medium"),
    (lambda r: r["dns"]["TXT"].update(answers=[]), "spf-missing", "medium"),
    (lambda r: r["dns"]["TXT"].update(answers=["v=spf1 -all", "v=spf1 mx -all"]), "spf-multiple", "medium"),
    (lambda r: r["dns"]["_dmarc"].update(answers=["v=DMARC1; p=quarantine"]), "dmarc-quarantine", "low"),
    (lambda r: r["dns"]["_dmarc"].update(answers=[]), "dmarc-missing", "medium"),
    (lambda r: r["tls_cert"].update(not_after="Oct  1 00:00:00 2026 GMT"), "cert-expired", "high"),
    (lambda r: r["tls_cert"].update(verified=False, error="self-signed certificate"), "cert-untrusted", "high"),
    (lambda r: r["http"]["headers"].update({"strict-transport-security": "max-age=300"}), "weak-hsts", "low"),
    (lambda r: r["http"]["headers"].pop("content-security-policy"), "missing-csp", "low"),
    (lambda r: r["tls_versions"].update({"TLSv1.1": {"accepted": True, "note": "TLSv1.1"}}), "weak-tls", "medium"),
])
def test_single_rules(mutate, key, sev):
    r = raw("good"); mutate(r)
    _, F, _, _ = run(r)
    assert key in F and F[key]["severity"] == sev, sorted(F)

def test_null_mx_skips_mail_findings():
    r = raw("bad"); r["dns"]["MX"]["answers"] = ["0 ."]
    _, F, _, _ = run(r)
    assert "no-mta-sts-tlsrpt" not in F

def test_untestable_tls_versions_are_skipped_and_unverified():
    r = raw("good"); r["tls_versions"]["TLSv1.0"] = {"accepted": None, "note": "client cannot test this version"}
    log, F, S, U = run(r)
    assert log["tls_versions"]["status"] == "skipped" and log["tls_versions"]["detail"]
    assert any("TLSv1.0" in u["item"] for u in U) and "Modern TLS only" not in S

def test_network_failures_are_logged_not_raised():
    r = raw("good"); r["errors"] = {"https_redirect": "URLError: timed out", "ct_subdomains": "HTTPError 502"}
    r.pop("http_plain"); r.pop("ct")
    log, F, S, U = run(r)
    assert log["https_redirect"]["status"] == "failed" and "timed out" in log["https_redirect"]["detail"]
    assert log["ct_subdomains"]["status"] == "failed"
    assert any(u["item"] == "HTTP→HTTPS redirect" for u in U)

def test_gather_offline_never_crashes(monkeypatch):
    def boom(*a, **k): raise OSError("network unreachable")
    for name in ("resolve", "http_get", "tls_cert", "tls_versions"): monkeypatch.setattr(collect, name, boom)
    monkeypatch.setattr(collect.urllib.request, "urlopen", boom)
    monkeypatch.setattr(collect, "__builtins__", collect.__builtins__)
    import time; monkeypatch.setattr(time, "sleep", lambda s: None)
    r = collect.gather("offline.test", log=lambda m: None)
    assert set(r["errors"]) >= {"dns_records", "tls_cert", "http_headers", "rdap", "ct_subdomains"}
    d = collect.draft(r)
    assert validate.validate(d) == [], validate.validate(d)
    assert len(d["check_log"]) == 15 and all(c["status"] in ("failed", "skipped") for c in d["check_log"])

@pytest.mark.parametrize("name", ["good", "bad"])
def test_drafts_validate_and_render(name):
    d = collect.draft(raw(name), "Fixture owner", NOW)
    assert validate.validate(d) == [], validate.validate(d)
    grade, cnt, html = gen.build(gen.normalize(d))
    assert "INCOMPLETE ASSESSMENT</b>" not in html and grade == ("A" if name == "good" else "D")

def test_domain_argument_validation(tmp_path):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "collect.py"), "not a domain;rm", "--out", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode != 0 and "not a domain" in r.stderr

def _online():
    try:
        socket.create_connection(("dns.google", 443), timeout=3).close(); return True
    except OSError: return False

@pytest.mark.live
@pytest.mark.skipif(os.environ.get("SCAFU_OFFLINE") == "1" or not _online(), reason="offline (or SCAFU_OFFLINE=1)")
def test_live_example_com(tmp_path):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "collect.py"), "example.com", "--out", str(tmp_path)], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    d = json.load(open(tmp_path / "findings.json"))
    assert validate.validate(d) == [] and len(d["check_log"]) == 15
    assert (tmp_path / "raw" / "collected.json").exists()
    assert next(c for c in d["check_log"] if c["id"] == "dns_records")["status"] == "ok"
