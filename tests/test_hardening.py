"""Hardening rules: bot-challenge/WAF pages, partial DNS, synthetic resolvers, shared-platform suffixes, CAA inheritance,
CT fallback and RDAP gaps. All offline (fixtures + monkeypatching)."""
import io, json, os, subprocess, urllib.error
import pytest
import collect, validate, gen
from test_collect import raw, run, NOW

VERCEL = {"status": 429, "headers": {"server": "Vercel", "x-vercel-mitigated": "challenge", "content-type": "text/html"},
          "body": "<!DOCTYPE html><html><head><title>Vercel Security Checkpoint</title></head><body>…</body></html>", "location": None}
CLOUDFLARE = {"status": 403, "headers": {"server": "cloudflare"}, "body": "<html><head><title>Just a moment...</title></head><body>cf-chl-opt</body></html>"}

def challenged(r, resp=VERCEL, paths=("/robots.txt", "/.well-known/security.txt", "/security.txt")):
    r["http"] = dict(resp, url="https://x/")
    for p in paths: r["files"][p] = {"status": resp["status"], "content_type": "text/html", "body": resp["body"], "headers": resp["headers"]}
    return r

# ------------------------------------------------------------------ challenge detection
@pytest.mark.parametrize("resp,hit", [
    (VERCEL, True), (CLOUDFLARE, True),
    ({"status": 403, "headers": {"cf-mitigated": "challenge"}, "body": ""}, True),
    ({"status": 403, "headers": {"server": "nginx"}, "body": "<h1>403 Forbidden</h1>"}, False),   # an ordinary 403 is a real observation
    ({"status": 200, "headers": {}, "body": "<p>we use challenge-platform in our docs</p>"}, False),  # body markers need a block status
    ({"status": 404, "headers": {}, "body": "not found"}, False), (None, False), ({"status": None, "error": "x"}, False),
])
def test_challenge_detector(resp, hit):
    assert bool(collect.challenge(resp)) is hit

def test_waf_challenge_never_becomes_header_findings():
    log, F, S, U = run(challenged(raw("good")))
    assert log["http_headers"]["status"] == "failed" and "bot-challenge" in log["http_headers"]["detail"]
    assert log["robots_security_txt"]["status"] == "failed"
    assert not {"missing-hsts", "weak-hsts", "missing-csp", "csp-unsafe", "acao-wildcard", "no-security-txt", "robots-sensitive"} & set(F)
    assert "HSTS" not in S and "Content-Security-Policy" not in S and "security.txt" not in S
    items = [u["item"] for u in U]
    assert "HSTS (Strict-Transport-Security)" in items and "Content-Security-Policy" in items and "robots.txt / security.txt" in items
    assert not any(u["reason"].startswith("Check failed") and "HTTPS security headers" in u["item"] for u in U)   # no duplicate generic entry
    assert "bot-challenge" in log["fingerprint"]["detail"]

def test_cloudflare_challenge_bad_fixture():
    log, F, S, U = run(challenged(raw("bad"), CLOUDFLARE))
    assert log["http_headers"]["status"] == "failed" and "missing-hsts" not in F and "csp-unsafe" not in F
    assert "version-disclosure" not in F or "meta generator" not in F["version-disclosure"]["evidence"]

def test_partial_challenge_security_txt_only():
    r = raw("bad"); challenged(r, paths=("/.well-known/security.txt", "/security.txt"))
    r["http"] = raw("bad")["http"]   # homepage was fine
    log, F, S, U = run(r)
    assert log["robots_security_txt"]["status"] == "ok" and "(challenge)" in log["robots_security_txt"]["detail"]
    assert "no-security-txt" not in F and "robots-sensitive" in F
    assert any(u["item"] == "robots.txt / security.txt" for u in U)

def test_plain_http_challenge_is_not_a_missing_redirect():
    r = raw("bad"); r["http_plain"] = dict(VERCEL)
    log, F, S, U = run(r)
    assert log["https_redirect"]["status"] == "failed" and "no-https-redirect" not in F
    assert any(u["item"] == "HTTP→HTTPS redirect" for u in U)

def test_challenge_draft_validates_and_mentions_limitation():
    d = collect.draft(challenged(raw("good")), "Fixture owner", NOW)
    assert validate.validate(d) == [], validate.validate(d)
    assert any("bot-challenge/WAF" in l for l in d["limitations"])
    gen.build(gen.normalize(d))

# ------------------------------------------------------------------ DNS honesty
def test_partial_dns_failure_is_not_ok_and_suppresses_mx_dependent_findings():
    r = raw("bad"); r["dns"].pop("MX"); r["dns_errors"] = {"MX": "DoH rcode 2 for bad.test MX"}
    log, F, S, U = run(r)
    assert log["dns_records"]["status"] == "failed" and "MX lookup failed" in log["dns_records"]["detail"]
    assert log["mta_sts_tlsrpt"]["status"] == "skipped" and "no-mta-sts-tlsrpt" not in F
    assert any("MX" in u["item"] for u in U)
    assert validate.validate(collect.draft(r, "x", NOW)) == []

def test_doh_servfail_raises(monkeypatch):
    body = json.dumps({"Status": 2, "Answer": []}).encode()
    monkeypatch.setattr(collect.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(body))
    with pytest.raises(RuntimeError, match="rcode 2"): collect.doh("x.test", "MX")

def test_dig_refuses_synthetic_resolver(monkeypatch):
    collect._DIG_TRUST.clear()
    monkeypatch.setattr(collect.shutil, "which", lambda n: "/usr/bin/dig")
    monkeypatch.setattr(collect.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="198.18.0.1\n", stderr=""))
    with pytest.raises(RuntimeError, match="synthetic"): collect.dig("example.test", "MX")
    collect._DIG_TRUST.clear()

def test_dig_parses_answers_with_status(monkeypatch):
    collect._DIG_TRUST.clear(); collect._DIG_TRUST["ok"] = True
    out = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nx.test.\t300\tIN\tMX\t10 mx.x.test.\nx.test.\t300\tIN\tCNAME\ty.test.\n"
    monkeypatch.setattr(collect.shutil, "which", lambda n: "/usr/bin/dig")
    monkeypatch.setattr(collect.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=out, stderr=""))
    assert collect.dig("x.test", "MX")["answers"] == ["10 mx.x.test."]
    monkeypatch.setattr(collect.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=";; status: SERVFAIL\n", stderr=""))
    with pytest.raises(RuntimeError, match="SERVFAIL"): collect.dig("x.test", "MX")
    collect._DIG_TRUST.clear()

# ------------------------------------------------------------------ shared platform suffixes
@pytest.mark.parametrize("dom,sfx", [("shop.netlify.app", "netlify.app"), ("a.b.vercel.app", "vercel.app"), ("me.github.io", "github.io"),
                                     ("netlify.app", None), ("www.example.com", None), ("example.io", None)])
def test_shared_suffix(dom, sfx):
    assert collect.shared_suffix(dom) == sfx

def test_shared_suffix_platform_findings_are_not_graded():
    r = raw("bad"); r["domain"] = "shop.netlify.app"; r["shared_suffix"] = "netlify.app"
    r.pop("rdap"); r["rdap_skip"] = "not applicable: customer subdomain of netlify.app"
    log, F, S, U = run(r)
    for k in ("no-dnssec", "spf-plus-all", "dmarc-none", "no-caa", "weak-tls", "cert-expiring", "no-https-redirect"):
        if k in F: assert F[k]["severity"] == "info" and F[k]["title"].startswith("Platform-level"), k
    assert F["missing-hsts"]["severity"] == "medium" and F["csp-unsafe"]["severity"] == "medium"   # site-controlled stays graded
    assert log["rdap"]["status"] == "skipped"
    d = collect.draft(r, "x", NOW)
    assert validate.validate(d) == [] and any("shared-platform" in l for l in d["limitations"])

def test_caa_inherited_from_parent_is_a_strength():
    r = raw("bad"); r["caa_climb"] = {"name": "parent.test", "answers": ['0 issue "letsencrypt.org"']}
    log, F, S, U = run(r)
    assert "no-caa" not in F and "CAA records" in S and "inherited" in log["caa"]["detail"]

# ------------------------------------------------------------------ CT and RDAP fallbacks (gather with network stubbed)
class _Resp(io.BytesIO): pass

def _stub_gather(monkeypatch, urlopen):
    def boom(*a, **k): raise OSError("offline")
    for n in ("resolve", "http_get", "tls_cert", "tls_versions"): monkeypatch.setattr(collect, n, boom)
    monkeypatch.setattr(collect.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(collect.socket, "create_connection", boom)
    import time; monkeypatch.setattr(time, "sleep", lambda s: None)

def test_ct_falls_back_to_cert_spotter(monkeypatch):
    def urlopen(req, *a, **k):
        u = req.full_url
        if "crt.sh" in u: raise urllib.error.HTTPError(u, 502, "Bad Gateway", {}, None)
        if "certspotter" in u: return _Resp(json.dumps([{"dns_names": ["x.test", "www.x.test"]}, {"dns_names": ["api.x.test"]}]).encode())
        raise OSError("offline")
    _stub_gather(monkeypatch, urlopen)
    r = collect.gather("x.test", log=lambda m: None)
    assert "ct_subdomains" not in r["errors"] and r["ct"]["names"] == ["api.x.test", "www.x.test", "x.test"]
    log, F, S, U = run(r)
    assert log["ct_subdomains"]["status"] == "ok" and "Cert Spotter" in log["ct_subdomains"]["detail"]

def test_rdap_no_service_is_skipped_not_failed(monkeypatch):
    def urlopen(req, *a, **k):
        u = req.full_url
        if "rdap.org" in u: raise urllib.error.HTTPError(u, 404, "Not Found", {}, None)
        raise OSError("offline")
    _stub_gather(monkeypatch, urlopen)
    r = collect.gather("www.x.io", log=lambda m: None)
    assert "rdap" not in r["errors"] and "x.io: HTTP 404" in r["rdap_skip"] and "www.x.io: HTTP 404" in r["rdap_skip"]
    log, *_ = run(r)
    assert log["rdap"]["status"] == "skipped"

def test_rdap_shared_suffix_not_queried(monkeypatch):
    calls = []
    def urlopen(req, *a, **k): calls.append(req.full_url); raise OSError("offline")
    _stub_gather(monkeypatch, urlopen)
    r = collect.gather("shop.netlify.app", log=lambda m: None)
    assert r["shared_suffix"] == "netlify.app" and "not applicable" in r["rdap_skip"] and not any("rdap.org" in c for c in calls)

def test_port80_failure_detail_names_the_collector_not_the_target(monkeypatch):
    _stub_gather(monkeypatch, lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    r = collect.gather("x.test", log=lambda m: None)
    assert "not evidence about the target" in r["errors"]["https_redirect"]
