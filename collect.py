#!/usr/bin/env python3
"""SCAFU passive collector.

Usage:  python3 collect.py <domain> --out <dir> [--authorized-by "Name"] [--timeout 15]

Runs every canonical check in checks.json PASSIVELY: public DNS (DNS-over-HTTPS via dns.google, falling back
to dig), one TLS handshake for the certificate, one openssl s_client handshake per protocol version, one HTTPS
GET of /, one plain-HTTP GET of / (redirect check), GETs of robots.txt and security.txt, crt.sh JSON and RDAP.
No port scanning, no brute force, no exploitation. Only use on domains you own or are authorized to assess.

Writes <dir>/raw/*.json (raw outputs) and <dir>/findings.json (a draft that passes validate.py).
Network failures are recorded in check_log as "failed" with a detail; the collector never crashes on them.
"""
import argparse, datetime as dt, json, os, re, shutil, socket, ssl, subprocess, sys, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
UA = "SCAFU-passive-check/1.0 (+https://sca-fu.com)"
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "fm1", "fm2", "fm3", "mail", "dkim", "smtp", "mandrill", "mxvault"]
ACTIONS = {"no-caa": "Publish CAA records", "spf-missing": "Publish an SPF record", "spf-multiple": "Merge SPF records", "spf-plus-all": "Replace +all with -all",
           "spf-neutral": "End SPF in -all", "spf-softfail": "Move SPF to -all", "dmarc-missing": "Publish a DMARC policy", "dmarc-none": "Enforce DMARC",
           "dmarc-quarantine": "Move DMARC to p=reject", "no-mta-sts-tlsrpt": "Publish MTA-STS / TLS-RPT", "no-dnssec": "Enable DNSSEC",
           "cert-untrusted": "Install a trusted certificate", "cert-expired": "Renew the certificate", "cert-expiring": "Check certificate renewal",
           "weak-tls": "Set minimum TLS 1.2", "missing-hsts": "Enable HSTS", "weak-hsts": "Raise HSTS max-age", "missing-csp": "Deploy a CSP",
           "csp-unsafe": "Remove unsafe-inline / unsafe-eval", "acao-wildcard": "Restrict Access-Control-Allow-Origin", "no-https-redirect": "Redirect HTTP to HTTPS",
           "no-security-txt": "Publish security.txt", "domain-expiring": "Renew the domain", "version-disclosure": "Hide version numbers"}
RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "DNSKEY": 48, "CAA": 257, "HTTPS": 65}

def checks():
    return json.load(open(os.path.join(HERE, "checks.json")))["required"]

# =================================================================== gathering (network)
def http_get(url, timeout=15, follow=False, max_bytes=300_000):
    """One GET. Returns {status, headers(lowercase), body, url, location} or raises."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        r = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:   # 3xx/4xx/5xx still carry headers
        r = e
    body = r.read(max_bytes) if hasattr(r, "read") else b""
    hdrs = {}
    for k, v in r.headers.items(): hdrs[k.lower()] = (hdrs[k.lower()] + ", " + v) if k.lower() in hdrs else v
    return {"url": url, "status": r.status if hasattr(r, "status") else r.code, "headers": hdrs,
            "location": hdrs.get("location"), "body": body.decode("utf-8", "replace")}

def doh(name, rtype, timeout=10):
    u = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": rtype, "do": 1})
    j = json.loads(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": UA}), timeout=timeout).read())
    ans = [a["data"] for a in j.get("Answer", []) if a.get("type") == RTYPES.get(rtype)]
    return {"status": j.get("Status"), "ad": bool(j.get("AD")), "answers": [a.strip('"') if rtype == "TXT" else a for a in ans],
            "txt_raw": ans if rtype == "TXT" else None, "via": "dns.google"}

def dig(name, rtype, timeout=10):
    if not shutil.which("dig"): raise RuntimeError("no DoH and dig not installed")
    out = subprocess.run(["dig", "+short", "+time=5", "+tries=1", name, rtype], capture_output=True, text=True, timeout=timeout).stdout
    ans = [l.strip() for l in out.splitlines() if l.strip()]
    if rtype == "TXT": ans = ["".join(re.findall(r'"((?:[^"\\]|\\.)*)"', a)) or a for a in ans]
    return {"status": 0, "ad": None, "answers": ans, "via": "dig"}

def resolve(name, rtype, timeout=10):
    try: return doh(name, rtype, timeout)
    except Exception as e1:
        try: return dig(name, rtype, timeout)
        except Exception as e2: raise RuntimeError(f"DoH failed ({e1}); dig failed ({e2})")

def tls_cert(host, timeout=15):
    ctx = ssl.create_default_context()
    out = {"verified": True, "error": None}
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert(); out["negotiated"] = t.version(); out["cipher"] = t.cipher()[0]
    except ssl.SSLCertVerificationError as e:
        out["verified"] = False; out["error"] = str(e.verify_message or e)
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, 443), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True); out["negotiated"] = t.version()
        pem = ssl.DER_cert_to_PEM_cert(der)
        txt = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-startdate"], input=pem, capture_output=True, text=True).stdout
        f = dict(l.split("=", 1) for l in txt.splitlines() if "=" in l)
        out.update(subject=f.get("subject", "").strip(), issuer=f.get("issuer", "").strip(), not_after=f.get("notAfter"), not_before=f.get("notBefore"), san=[])
        return out
    flat = lambda x: ", ".join(f"{k}={v}" for rdn in x for k, v in rdn)
    out.update(subject=flat(c.get("subject", ())), issuer=flat(c.get("issuer", ())), not_after=c.get("notAfter"),
               not_before=c.get("notBefore"), san=[v for k, v in c.get("subjectAltName", ()) if k == "DNS"])
    return out

def tls_versions(host, timeout=12):
    if not shutil.which("openssl"): raise RuntimeError("openssl not installed")
    res = {}
    for flag, name in (("-tls1", "TLSv1.0"), ("-tls1_1", "TLSv1.1"), ("-tls1_2", "TLSv1.2"), ("-tls1_3", "TLSv1.3")):
        cmd = ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host, flag]
        if flag in ("-tls1", "-tls1_1"): cmd += ["-cipher", "DEFAULT:@SECLEVEL=0"]
        try:
            p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
            o = p.stdout + p.stderr
            if re.search(r"no protocols available|unknown option|unsupported protocol|ssl/tls alert.*?no protocols", o, re.I) and "Protocol  :" not in o and "Protocol:" not in o:
                res[name] = {"accepted": None, "note": "client cannot test this version"}
            else:
                m = re.search(r"Protocol\s*:\s*(\S+)", o); cph = re.search(r"Cipher\s*(?:is|:)\s*(\S+)", o)
                ok = bool(m and m.group(1).replace("TLSv1", "TLSv1.0") .replace("TLSv1.0.", "TLSv1.") == name) and bool(cph and cph.group(1) not in ("0000", "(NONE)"))
                res[name] = {"accepted": ok, "note": (m.group(1) if m else "handshake failed")}
        except subprocess.TimeoutExpired:
            res[name] = {"accepted": None, "note": "timeout"}
    return res

def gather(domain, timeout=15, log=print):
    """Run every check; returns raw dict. Errors are stored under raw['errors'][check_id]."""
    raw = {"domain": domain, "collected_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "errors": {}, "dns": {}}
    def step(cid, fn):
        try: fn()
        except Exception as e:
            raw["errors"][cid] = f"{type(e).__name__}: {e}"[:300]; log(f"  ! {cid}: {raw['errors'][cid]}")
    def dns_set(key, name, rtype):
        r = resolve(name, rtype, timeout); raw["dns"][key] = r; return r
    log(f"[collect] {domain}: DNS")
    step("dns_records", lambda: [dns_set(t, domain, t) for t in ("A", "AAAA", "MX", "NS", "TXT", "HTTPS")])
    step("caa", lambda: dns_set("CAA", domain, "CAA"))
    step("spf", lambda: raw["dns"].get("TXT") or dns_set("TXT", domain, "TXT"))
    def dkim():
        raw["dkim"] = {}
        probe = resolve(f"scafu-nonexistent-probe._domainkey.{domain}", "TXT", timeout)["answers"]   # wildcard detection
        raw["dkim_wildcard"] = bool(probe)
        for sel in DKIM_SELECTORS:
            r = resolve(f"{sel}._domainkey.{domain}", "TXT", timeout)
            keys = [a for a in r["answers"] if re.search(r"(^|;)\s*(v=DKIM1|k=|p=)", a, re.I)]
            if keys and keys != probe: raw["dkim"][sel] = keys
    step("dkim", dkim)
    step("dmarc", lambda: dns_set("_dmarc", f"_dmarc.{domain}", "TXT"))
    step("mta_sts_tlsrpt", lambda: (dns_set("_mta-sts", f"_mta-sts.{domain}", "TXT"), dns_set("_smtp._tls", f"_smtp._tls.{domain}", "TXT")))
    step("dnssec", lambda: (dns_set("DS", domain, "DS"), dns_set("DNSKEY", domain, "DNSKEY")))
    log("[collect] TLS")
    step("tls_cert", lambda: raw.__setitem__("tls_cert", tls_cert(domain, timeout)))
    step("tls_versions", lambda: raw.__setitem__("tls_versions", tls_versions(domain, timeout)))
    log("[collect] crt.sh / RDAP")
    def ct():
        last = None
        for attempt in range(3):   # crt.sh is often briefly overloaded (502/503)
            try:
                j = json.loads(urllib.request.urlopen(urllib.request.Request(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", headers={"User-Agent": UA}), timeout=max(timeout, 40)).read()); break
            except Exception as e:
                last = e; __import__("time").sleep(3 * (attempt + 1))
        else: raise last
        names = sorted({n.strip().lower() for c in j for n in str(c.get("name_value", "")).split("\n") if n.strip()})
        raw["ct"] = {"certificates": len(j), "names": names}
    step("ct_subdomains", ct)
    def rdap():
        r = json.loads(urllib.request.urlopen(urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"User-Agent": UA, "Accept": "application/rdap+json"}), timeout=timeout).read())
        ev = {e.get("eventAction"): e.get("eventDate") for e in r.get("events", [])}
        reg = next((e for e in r.get("entities", []) if "registrar" in e.get("roles", [])), {})
        regname = next((v[3] for v in (reg.get("vcardArray") or [None, []])[1] if v and v[0] == "fn"), None)
        raw["rdap"] = {"ldhName": r.get("ldhName"), "status": r.get("status", []), "events": ev, "registrar": regname,
                       "nameservers": [n.get("ldhName") for n in r.get("nameservers", [])], "secureDNS": r.get("secureDNS", {})}
    step("rdap", rdap)
    log("[collect] HTTP")
    step("http_headers", lambda: raw.__setitem__("http", http_get(f"https://{domain}/", timeout)))
    if "http" not in raw: raw["errors"].setdefault("fingerprint", "no HTTPS response to fingerprint (" + raw["errors"].get("http_headers", "") + ")")
    step("https_redirect", lambda: raw.__setitem__("http_plain", {k: v for k, v in http_get(f"http://{domain}/", timeout).items() if k != "body"}))
    def files():
        raw["files"] = {}
        for path in ("/robots.txt", "/.well-known/security.txt", "/security.txt"):
            try:
                r = http_get(f"https://{domain}{path}", timeout, follow=True, max_bytes=50_000)
                raw["files"][path] = {"status": r["status"], "content_type": r["headers"].get("content-type", ""), "body": r["body"][:5000]}
            except Exception as e:
                raw["files"][path] = {"status": None, "error": str(e)[:200]}
        if all(v.get("status") is None for v in raw["files"].values()): raise RuntimeError("all file requests failed: " + raw["files"]["/robots.txt"].get("error", ""))
    step("robots_security_txt", files)
    return raw

# =================================================================== analysis (pure; unit-tested with fixtures)
def _parse_cert_date(s):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try: return dt.datetime.strptime(re.sub(r"\s+", " ", s.strip()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        except Exception: pass
    return None

def analyze(raw, now=None):
    """Turn raw collector output into (check_log, findings, strengths, unverified)."""
    d = raw["domain"]; now = now or dt.datetime.now(dt.timezone.utc)
    err = raw.get("errors", {}); dns = raw.get("dns", {})
    names = {c["id"]: c["name"] for c in checks()}
    log, F, S, U = {}, [], [], []
    def ok(cid, detail): log[cid] = {"id": cid, "check": names[cid], "status": "ok", "detail": detail}
    def failed(cid, detail): log[cid] = {"id": cid, "check": names[cid], "status": "failed", "detail": detail}
    def skipped(cid, detail): log[cid] = {"id": cid, "check": names[cid], "status": "skipped", "detail": detail}
    def find(key, sev, title, desc, ev, imp, rem, **kw):
        F.append(dict(key=key, severity=sev, title=title, description=desc, evidence=ev, impact=imp, remediation=rem, **kw))
    ans = lambda k: (dns.get(k) or {}).get("answers") or []
    mx_real = [m for m in ans("MX") if not re.fullmatch(r"0\s+\.?", m.strip())]   # RFC 7505 null MX = no mail
    for cid in err: failed(cid, err[cid])

    # --- dns_records
    if "dns_records" not in err:
        ok("dns_records", f"A {len(ans('A'))}, AAAA {len(ans('AAAA'))}, MX {len(ans('MX'))}, NS {len(ans('NS'))}, TXT {len(ans('TXT'))} (via {dns.get('A', {}).get('via', '?')})")
    # --- caa
    if "caa" not in err:
        caa = ans("CAA"); ok("caa", f"{len(caa)} CAA record(s)")
        if caa: S.append({"title": "CAA records", "detail": "Certificate issuance is restricted: " + "; ".join(caa[:4])})
        else: find("no-caa", "low", "No CAA records", "No CAA records are published, so any public CA may issue certificates for the domain.",
                   f"{d} CAA  →  (none)", "Any public CA may issue for the domain; CAA restricts issuance to the CAs actually in use.",
                   ["Publish CAA records for the CAs you use (e.g. letsencrypt.org, pki.goog).", "Add an iodef contact."])
    # --- spf
    if "spf" not in err and "dns_records" not in err or (dns.get("TXT") and "spf" not in err):
        spf = [t for t in ans("TXT") if t.lower().startswith("v=spf1")]
        mx = mx_real
        if not spf:
            ok("spf", "no SPF record")
            find("spf-missing", "medium" if mx else "low", "No SPF record", "The domain publishes no SPF record" + ("" if mx else " (no MX either; a v=spf1 -all record stops spoofing of a non-mail domain)") + ".",
                 f"{d} TXT  →  no v=spf1 record", "Receivers cannot tell which servers may send mail for the domain, which makes spoofing easier.",
                 ["Publish an SPF record listing your senders, ending in -all." if mx else "Publish \"v=spf1 -all\" if the domain sends no mail."])
        elif len(spf) > 1:
            ok("spf", f"{len(spf)} SPF records")
            find("spf-multiple", "medium", "Multiple SPF records", "More than one v=spf1 record is published, which is a permanent SPF error (RFC 7208).",
                 "\n".join(spf), "SPF evaluation fails (permerror), so SPF gives no protection.", ["Merge them into a single SPF record."])
        else:
            rec = spf[0]; m = re.search(r"([~+?-])all\b", rec); q = m.group(1) if m else None
            ok("spf", rec)
            if q == "+": find("spf-plus-all", "high", "SPF allows any sender (+all)", "The SPF record ends in +all, authorising every server on the internet to send as the domain.", rec,
                              "Anyone can send SPF-passing mail as this domain.", ["Replace +all with -all after listing legitimate senders."])
            elif q == "?" or q is None: find("spf-neutral", "medium", "SPF has no enforcing 'all' qualifier", "The SPF record ends in ?all or has no all mechanism, so unauthorised senders are neutral.", rec,
                                             "SPF does not reject or flag spoofed mail.", ["End the record in -all (or ~all while monitoring)."])
            elif q == "~": find("spf-softfail", "low", "SPF ends in ~all (softfail)", "The SPF record ends in a softfail qualifier rather than a hard fail.", rec,
                                "Unauthorised senders are soft-failed rather than rejected.", ["After confirming all senders, switch to -all and enforce DMARC p=reject."])
            else: S.append({"title": "SPF hard fail", "detail": "SPF ends in -all."})
    # --- dkim
    if "dkim" not in err:
        dk = raw.get("dkim") or {}
        if dk:
            ok("dkim", "selectors found: " + ", ".join(sorted(dk)))
            S.append({"title": "DKIM published", "detail": "DKIM keys found at selector(s) " + ", ".join(sorted(dk)) + "."})
        else:
            ok("dkim", f"no key at {len(DKIM_SELECTORS)} common selectors" + (" (wildcard TXT under _domainkey ignored)" if raw.get("dkim_wildcard") else "") + "; a custom selector may still exist, so this is not a finding")
    # --- dmarc
    if "dmarc" not in err:
        dm = [t for t in ans("_dmarc") if t.lower().startswith("v=dmarc1")]
        if not dm:
            ok("dmarc", "no DMARC record")
            find("dmarc-missing", "medium", "No DMARC record", "No DMARC policy is published at _dmarc." + d + ".", f"_dmarc.{d} TXT  →  (none)",
                 "Receivers get no policy for mail that fails SPF/DKIM, and you get no reports about spoofing.",
                 ["Publish v=DMARC1; p=none; rua=mailto:… to start monitoring, then move to quarantine and reject."])
        else:
            rec = dm[0]; m = re.search(r"\bp\s*=\s*(\w+)", rec, re.I); p = (m.group(1).lower() if m else "none")
            ok("dmarc", rec)
            if p == "none": find("dmarc-none", "medium", "DMARC policy is p=none (monitor only)", "DMARC is published but does not ask receivers to act on failing mail.", f"_dmarc.{d} TXT\n{rec}",
                                 "Spoofed mail is still delivered normally.", ["Review aggregate reports, then move to p=quarantine and p=reject."])
            elif p == "quarantine": find("dmarc-quarantine", "low", "DMARC at p=quarantine (not reject)", "DMARC is enforced at quarantine rather than reject.", f"_dmarc.{d} TXT\n{rec}",
                                         "Mail that fails DMARC is quarantined rather than rejected outright.", ["After monitoring, move to p=reject."])
            else: S.append({"title": "DMARC reject", "detail": "DMARC is enforced at p=reject."})
    # --- mta-sts / tls-rpt
    if "mta_sts_tlsrpt" not in err:
        sts = [t for t in ans("_mta-sts") if "v=stsv1" in t.lower()]; rpt = [t for t in ans("_smtp._tls") if "v=tlsrptv1" in t.lower()]
        ok("mta_sts_tlsrpt", f"MTA-STS {'present' if sts else 'absent'}, TLS-RPT {'present' if rpt else 'absent'}")
        if mx_real and (not sts or not rpt):
            miss = " and ".join(x for x, v in (("MTA-STS", sts), ("TLS-RPT", rpt)) if not v)
            find("no-mta-sts-tlsrpt", "low", f"No {miss}", f"The domain receives mail but publishes no {miss} record.",
                 f"_mta-sts.{d} TXT    →  {sts[0] if sts else '(none)'}\n_smtp._tls.{d} TXT  →  {rpt[0] if rpt else '(none)'}",
                 "Sending servers are not told to require TLS for inbound mail, and TLS failures are not reported.",
                 ["Publish an MTA-STS policy and TXT record.", "Publish a TLS-RPT record (v=TLSRPTv1; rua=mailto:…)."])
        elif sts and rpt: S.append({"title": "MTA-STS and TLS-RPT", "detail": "Inbound mail TLS policy and reporting are published."})
    # --- dnssec
    if "dnssec" not in err:
        ds, key = ans("DS"), ans("DNSKEY"); ad = (dns.get("A") or {}).get("ad")
        rd = (raw.get("rdap") or {}).get("secureDNS", {}).get("delegationSigned")
        ok("dnssec", f"DS {len(ds)}, DNSKEY {len(key)}, resolver AD={ad}, RDAP delegationSigned={rd}")
        if ds and key: S.append({"title": "DNSSEC", "detail": "The delegation is signed (DS and DNSKEY published)."})
        else: find("no-dnssec", "medium", "DNSSEC not enabled", "No DS/DNSKEY records are published, so the zone is unsigned.",
                   f"{d} DS      →  {ds or '[]'}\n{d} DNSKEY  →  {len(key)} record(s)" + (f"\nRDAP secureDNS.delegationSigned = {str(rd).lower()}" if rd is not None else ""),
                   "Resolvers cannot validate DNS answers for the domain, so responses are not protected against spoofing.",
                   ["Enable DNSSEC at the DNS host and publish the DS record at the registrar."])
    # --- tls cert
    if "tls_cert" not in err and raw.get("tls_cert"):
        c = raw["tls_cert"]; exp = _parse_cert_date(c.get("not_after") or "")
        days = (exp - now).days if exp else None
        ok("tls_cert", f"{c.get('subject')} · issuer {c.get('issuer')} · expires {c.get('not_after')}" + ("" if c.get("verified") else f" · NOT TRUSTED: {c.get('error')}"))
        ev = f"Subject  {c.get('subject')}\nIssuer   {c.get('issuer')}\nValid    {c.get('not_before')} → {c.get('not_after')}" + (f"\nSAN      {', '.join(c.get('san') or [])[:300]}" if c.get("san") else "")
        if not c.get("verified"):
            find("cert-untrusted", "high", "TLS certificate is not trusted", f"Certificate verification failed: {c.get('error')}.", ev,
                 "Browsers show a full-page warning; users may be trained to click through it.", ["Install a valid certificate for the hostname from a public CA."])
        elif days is not None and days < 0:
            find("cert-expired", "high", "TLS certificate expired", f"The certificate expired {-days} day(s) ago.", ev, "Browsers block the site with a certificate error.", ["Renew the certificate and fix auto-renewal."])
        elif days is not None and days <= 30:
            find("cert-expiring", "medium", f"TLS certificate expires in {days} day(s)", "The certificate expires within 30 days.", ev,
                 "If renewal fails, browsers will block the site.", ["Confirm automatic renewal is working, or renew now."])
        elif days is not None: S.append({"title": "Valid TLS certificate", "detail": f"Trusted certificate from {(re.search(r'(?:organizationName|O)=([^,]+)', c.get('issuer') or '') or re.search('(.*)', c.get('issuer') or '')).group(1)}, {days} days left."})
    # --- tls versions
    if "tls_versions" not in err and raw.get("tls_versions"):
        v = raw["tls_versions"]; acc = [k for k, x in v.items() if x.get("accepted")]; unk = [k for k, x in v.items() if x.get("accepted") is None]
        detail = "; ".join(f"{k}: {'accepted' if x.get('accepted') else 'unknown (' + x.get('note', '') + ')' if x.get('accepted') is None else 'refused'}" for k, x in v.items())
        legacy = [k for k in ("TLSv1.0", "TLSv1.1") if v.get(k, {}).get("accepted")]
        if unk: skipped("tls_versions", detail + ". Untestable versions are listed as unverified.")
        else: ok("tls_versions", detail)
        if legacy: find("weak-tls", "medium", "Legacy TLS versions accepted (" + ", ".join(legacy) + ")", "The server completes handshakes with deprecated TLS versions.", detail,
                        "Deprecated protocols have known weaknesses and fail compliance baselines.", ["Set the minimum TLS version to 1.2."])
        elif "TLSv1.3" in acc and not unk: S.append({"title": "Modern TLS only", "detail": "TLS 1.3 accepted; TLS 1.0 and 1.1 refused."})
        if unk: U.append({"item": "TLS versions: " + ", ".join(unk), "reason": "The scanning client could not test these versions.", "confirm": "check the minimum TLS version setting on the server or CDN."})
    # --- ct
    if "ct_subdomains" not in err and raw.get("ct") is not None:
        n = raw["ct"]["names"]; ok("ct_subdomains", f"{raw['ct']['certificates']} certificates, {len(n)} unique names")
        if n: find("ct-names", "info", "Names in Certificate Transparency logs", f"{len(n)} unique names appear in CT logs for {d}.", "\n".join(n[:40]) + (f"\n… and {len(n) - 40} more" if len(n) > 40 else ""),
                   "None directly; CT logs are public and show which hostnames exist.", ["Review the list for forgotten hosts."])
    # --- http headers
    h = (raw.get("http") or {}).get("headers") or {}
    if "http_headers" not in err and raw.get("http"):
        ok("http_headers", f"GET https://{d}/ → {raw['http']['status']}")
        hsts = h.get("strict-transport-security")
        if not hsts: find("missing-hsts", "medium", "No HSTS (Strict-Transport-Security) header", f"The HTTPS response to https://{d}/ carries no Strict-Transport-Security header.",
                          f"GET https://{d}/  →  {raw['http']['status']}\nStrict-Transport-Security:  (not present)", "Browsers may make first-visit plain-HTTP requests, which are open to SSL stripping.",
                          ["Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", "Consider HSTS preload once stable."])
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts); age = int(m.group(1)) if m else 0
            if age < 15552000: find("weak-hsts", "low", "HSTS max-age is short", f"HSTS is sent with max-age={age} (under 180 days).", f"Strict-Transport-Security: {hsts}",
                                    "Protection lapses quickly between visits.", ["Raise max-age to at least 31536000."])
            else: S.append({"title": "HSTS", "detail": f"Strict-Transport-Security: {hsts}"})
        csp = h.get("content-security-policy")
        if not csp: find("missing-csp", "low", "No Content-Security-Policy", "No CSP header is sent.", "Content-Security-Policy:  (not present)",
                         "There is no browser-enforced limit on script sources if an injection bug exists.", ["Deploy a CSP, starting in Report-Only mode."])
        else:
            bad = [x for x in ("'unsafe-inline'", "'unsafe-eval'") if x in csp.lower()]
            if bad: find("csp-unsafe", "medium", "Content-Security-Policy allows " + " and ".join(bad), "A CSP is present but permits " + " and ".join(bad) + ".",
                         "Content-Security-Policy: " + csp[:600], "Allowing inline script and eval largely negates the XSS protection the policy would otherwise give.",
                         ["Move inline scripts to files or use nonces/hashes.", "Drop 'unsafe-eval' unless a dependency truly needs it."])
            else: S.append({"title": "Content-Security-Policy", "detail": "A CSP without unsafe-inline/unsafe-eval is deployed."})
        if h.get("access-control-allow-origin", "").strip() == "*":
            find("acao-wildcard", "low", "Access-Control-Allow-Origin: * on HTML pages", "The homepage sends a wildcard ACAO header.", f"GET https://{d}/\nAccess-Control-Allow-Origin: *",
                 "Low impact unless credentialed APIs share the origin.", ["Restrict or remove ACAO on HTML responses."])
    # --- https redirect
    if "https_redirect" not in err and raw.get("http_plain"):
        p = raw["http_plain"]; loc = p.get("location") or ""
        ok("https_redirect", f"GET http://{d}/ → {p['status']} {loc}".strip())
        if 300 <= (p["status"] or 0) < 400 and loc.lower().startswith("https://"): S.append({"title": "HTTPS redirect", "detail": f"Plain HTTP redirects to {loc}."})
        else: find("no-https-redirect", "medium", "HTTP does not redirect to HTTPS", f"A plain-HTTP request to http://{d}/ is not redirected to HTTPS.", f"GET http://{d}/  →  {p['status']} {loc}",
                   "Visitors who type the bare domain stay on unencrypted HTTP.", ["Redirect all HTTP requests to HTTPS with a 301."])
    elif "https_redirect" in err:
        U.append({"item": "HTTP→HTTPS redirect", "reason": "Plain-HTTP behaviour could not be observed: " + err["https_redirect"], "confirm": "check that HTTP requests are redirected to HTTPS."})
    # --- robots / security.txt
    if "robots_security_txt" not in err and raw.get("files") is not None:
        fl = raw["files"]; st = lambda p: (fl.get(p) or {}).get("status")
        sec = next((p for p in ("/.well-known/security.txt", "/security.txt") if st(p) == 200 and "contact:" in (fl[p].get("body") or "").lower()), None)
        ok("robots_security_txt", f"robots.txt {st('/robots.txt')}, /.well-known/security.txt {st('/.well-known/security.txt')}, /security.txt {st('/security.txt')}")
        if sec: S.append({"title": "security.txt", "detail": f"Published at {sec}."})
        else: find("no-security-txt", "low", "No security.txt", "No RFC 9116 security.txt with a Contact field is published.",
                   f"GET /.well-known/security.txt  →  {st('/.well-known/security.txt')}\nGET /security.txt              →  {st('/security.txt')}",
                   "There is no published contact for reporting security issues.", ["Publish /.well-known/security.txt with Contact and Expires fields."])
        rb = (fl.get("/robots.txt") or {}).get("body", "") if st("/robots.txt") == 200 else ""
        sens = sorted({m for m in re.findall(r"(?im)^\s*disallow:\s*(\S+)", rb) if re.search(r"admin|backup|private|secret|\.git|\.env|config|db|sql", m, re.I)})
        if sens: find("robots-sensitive", "info", "robots.txt names sensitive-looking paths", "robots.txt lists paths that hint at sensitive content. They were not requested.",
                      "\n".join(f"Disallow: {x}" for x in sens[:20]), "Discloses path names to anyone who reads robots.txt.", ["Do not rely on robots.txt for secrecy; protect or remove these paths."])
    # --- rdap
    if "rdap" not in err and raw.get("rdap"):
        r = raw["rdap"]; ok("rdap", f"registrar {r.get('registrar')}, status {', '.join(r.get('status', []))}, expires {r.get('events', {}).get('expiration')}")
        if any("transfer prohibited" in s.lower() or "transferprohibited" in s.lower().replace(" ", "") for s in r.get("status", [])):
            S.append({"title": "Registrar transfer lock", "detail": "clientTransferProhibited is set."})
        exp = r.get("events", {}).get("expiration")
        try:
            days = (dt.datetime.fromisoformat(exp.replace("Z", "+00:00")) - now).days
            if days <= 30: find("domain-expiring", "high" if days < 0 else "medium", f"Domain registration expires in {days} day(s)", "The domain registration is close to expiry.", f"RDAP expiration {exp}",
                                "If it lapses, the domain and its email can be lost or taken over.", ["Renew the domain and enable auto-renew."])
        except Exception: pass
    # --- fingerprint
    if "fingerprint" not in err:
        if raw.get("http"):
            body = raw["http"].get("body") or ""
            fp = {k: h[k] for k in ("server", "x-powered-by", "x-generator", "via") if h.get(k)}
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if gen: fp["meta generator"] = gen.group(1)
            ok("fingerprint", "; ".join(f"{k}: {v}" for k, v in fp.items()) or "no technology headers")
            if fp: find("fingerprint", "info", "Technology fingerprint", "Technology identifiers seen in the homepage response. No CVE matching was performed.",
                        "\n".join(f"{k}: {v}" for k, v in fp.items()), "None directly.", ["Optionally suppress version details in headers."])
            ver = [f"{k}: {v}" for k, v in fp.items() if re.search(r"/\d+(\.\d+)+|\b\d+\.\d+\.\d+\b", v)]
            if ver: find("version-disclosure", "low", "Software version disclosed", "Exact software versions are disclosed in the response.", "\n".join(ver),
                         "Helps attackers match the host to known vulnerabilities.", ["Remove version numbers from Server / X-Powered-By headers."])
        else: failed("fingerprint", "no HTTPS response to fingerprint")
    # --- every required check must be logged
    for cid, nm in names.items():
        if cid not in log: skipped(cid, "not evaluated (dependency failed)")
    for cid, c in log.items():
        if c["status"] == "failed" and cid not in ("https_redirect",):
            U.append({"item": names[cid], "reason": "Check failed: " + c["detail"], "confirm": "re-run the collector or verify manually."})
    for f in F:
        if f["key"] in ACTIONS: f["action"] = ACTIONS[f["key"]]
    order = [c["id"] for c in checks()]
    return [log[c] for c in order], F, S, U

def draft(raw, authorized_by=None, now=None):
    log, F, S, U = analyze(raw, now)
    d = raw["domain"]; dns = raw.get("dns", {})
    rows = [[k, ", ".join(v.get("answers") or []) or "(none)"] for k, v in dns.items()]
    app = [{"title": f"DNS answers (from raw/collected.json, via {(dns.get('A') or {}).get('via', 'DoH')})", "type": "table",
            "content": {"columns": ["Query", "Answer"], "widths": ["22%", None], "rows": rows}}] if rows else []
    if raw.get("rdap"):
        r = raw["rdap"]
        app.append({"title": "Registry RDAP (rdap.org)", "type": "records", "content": [["Domain", r.get("ldhName")], ["Registrar", r.get("registrar")], ["Status", ", ".join(r.get("status", []))],
                    ["Registered", r.get("events", {}).get("registration")], ["Expires", r.get("events", {}).get("expiration")], ["Nameservers", ", ".join(n for n in r.get("nameservers", []) if n)],
                    ["DNSSEC (delegationSigned)", str(r.get("secureDNS", {}).get("delegationSigned"))]], "break": False})
    return {
        "_comment": "DRAFT generated by collect.py. Review every finding before sending. Confirm authorization.",
        "target": d, "date": dt.date.today().isoformat(),
        "authorized_by": authorized_by or "NOT CONFIRMED: set authorized_by before sharing",
        "scope": d, "methods": [f"{c['name']}: {c['method']}" for c in checks()],
        "out_of_scope": ["Port scanning", "Brute force of any kind (only a fixed list of common DKIM selectors is queried)", "Exploitation or intrusive testing", "Authenticated testing"],
        "check_log": log, "findings": F, "strengths": S, "unverified": U,
        "limitations": ["This was a passive assessment only; issues that only appear under active testing are out of scope.",
                        "DKIM is checked only at common selectors; a custom selector may exist.",
                        f"Results reflect the state observed at {raw.get('collected_at')}."],
        "appendix": app}

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain"); ap.add_argument("--out", required=True)
    ap.add_argument("--authorized-by", help="who authorized the assessment (shown on the report)")
    ap.add_argument("--timeout", type=int, default=15)
    a = ap.parse_args()
    dom = a.domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", dom): sys.exit(f"error: {a.domain!r} is not a domain name")
    rawdir = os.path.join(a.out, "raw"); os.makedirs(rawdir, exist_ok=True)
    raw = gather(dom, a.timeout, log=lambda m: print(m, file=sys.stderr))
    json.dump(raw, open(os.path.join(rawdir, "collected.json"), "w"), indent=1, default=str)
    for k in ("dns", "tls_cert", "tls_versions", "ct", "rdap", "http", "http_plain", "files", "dkim"):
        if k in raw: json.dump(raw[k], open(os.path.join(rawdir, f"{k}.json"), "w"), indent=1, default=str)
    f = draft(raw, a.authorized_by)
    p = os.path.join(a.out, "findings.json"); json.dump(f, open(p, "w"), indent=1, ensure_ascii=False)
    bad = [c for c in f["check_log"] if c["status"] != "ok"]
    print(f"[collect] wrote {p}: {len(f['findings'])} findings, {len(f['strengths'])} strengths, {len(bad)} failed/skipped checks", file=sys.stderr)
    print(p)

if __name__ == "__main__":
    main()
