# Installing SCAFU on a new Grok Bot box

These steps set up the passive Surface Check report pipeline on a fresh box (or any Debian/Ubuntu machine). Nothing here needs an API key, account or secret: every data source the collector uses is public (dns.google, crt.sh, Cert Spotter, rdap.org, and the target's own public HTTPS/TLS responses).

> **Authorized, passive use only.** Only assess domains you own or have written permission to assess. Record who authorized each run with `--authorized-by`. The pipeline makes ordinary DNS lookups, single TLS handshakes and a few GET requests. It does no port scanning, brute force, exploitation or authenticated testing.

## 1. Clone

The bot expects the repository at **`/workspace/scafu-grok-bot`**. The skills in `bot-skills/` use this path.

```bash
cd /workspace
[ -d scafu-grok-bot/.git ] && git -C scafu-grok-bot pull --ff-only || git clone https://github.com/canboigay/scafu-grok-bot
cd scafu-grok-bot
chmod +x scafu.sh run_tests.sh      # needed after a GitHub-API/zip download; harmless otherwise
```

## 2. System dependencies

| Need | Package (Debian/Ubuntu) | Used for |
|---|---|---|
| Python 3.9+ with venv | `python3 python3-venv` | collector, validator, generator (standard library only) |
| openssl CLI | `openssl` | one handshake per TLS version |
| dig (optional) | `dnsutils` | DNS fallback if DNS-over-HTTPS fails |
| headless Chrome or Chromium | `chromium` (or Google Chrome) | `report.pdf` |
| poppler-utils | `poppler-utils` | `preview-*.png` and page count |
| Public Suffix List (optional) | `publicsuffix` | finds more shared-hosting suffixes than the built-in list |

Check what is already there, then install only what is missing:

```bash
for t in python3 openssl dig pdftoppm pdfinfo; do command -v $t >/dev/null && echo "ok   $t" || echo "MISS $t"; done
command -v chromium || command -v chromium-browser || command -v google-chrome || command -v google-chrome-stable || echo "MISS chrome/chromium"
python3 -c 'import venv' 2>/dev/null && echo "ok   python3-venv" || echo "MISS python3-venv"

sudo apt-get update && sudo apt-get install -y python3 python3-venv openssl dnsutils poppler-utils chromium publicsuffix
```

If you can't install Chrome/Chromium, run the pipeline with `--no-pdf`. You still get `report.html`.

## 3. Test (offline)

```bash
SCAFU_OFFLINE=1 bash run_tests.sh   # creates .venv, installs pytest, runs the fixture suite with no network
bash run_tests.sh                   # optional: also runs the live example.com smoke test
```

All tests should pass. Exactly one test (the live example.com smoke test) is skipped when `SCAFU_OFFLINE=1` is set.

## 4. First report

```bash
bash scafu.sh example.com --out /tmp/scafu-smoke --no-history      # smoke test on the IANA example domain
bash scafu.sh yourdomain.com --authorized-by "Jane Doe (owner)"     # real run -> reports/yourdomain.com/
```

The output is `reports/<domain>/report.html`, `report.pdf`, `preview-1.png`, `preview-2.png`, `findings.json` (the draft) and `raw/` (every raw response).

The summary lists every check that is not `ok`. **The findings are a draft.** Read them before you share the report.

Useful flags: `--out DIR`, `--allow-incomplete` (render despite coverage gaps, with an INCOMPLETE banner), `--no-pdf`, `--no-history`, `--history-dir DIR`, `--auto-cap`.
Environment: `SCAFU_REPORTS_DIR` (default `reports/`), `SCAFU_OFFLINE=1` (tests), `SCAFU_PSL_FILE` (path to a Public Suffix List file), `SCAFU_PORT80_CONTROL` (control host for the port-80 egress check, default `example.com`).

## 5. When a WAF or bot challenge blocks the collector

Sites behind Vercel, Cloudflare, AWS WAF, Incapsula, Sucuri, DataDome or PerimeterX often answer automated clients with a challenge page (for example HTTP 429 with `x-vercel-mitigated: challenge`). The collector detects these pages and handles them as follows:

- `http_headers` / `robots_security_txt` / `https_redirect` are marked **failed** with "bot-challenge" in the detail;
- **no** HSTS/CSP/security.txt/redirect finding is raised from the challenge page;
- the affected items are listed under **Unverified**, and a limitation is added.

**Do not** try to get around the challenge (no header spoofing, solver services, rotating IPs or headless tricks). To fill the gap honestly, make a **reviewed copy**:

1. Open the site in a normal browser session (the bot's own desktop browser is fine). In DevTools → Network, reload `/` and copy the response headers. Also open `/.well-known/security.txt` and `/robots.txt`.
2. Save what you saw as plain text under `reports/<domain>-reviewed/raw-supplement/` (for example `browser-headers.txt`), with the date and the browser used.
3. Copy the draft: `cp -r reports/<domain> reports/<domain>-reviewed` and edit `reports/<domain>-reviewed/findings.json`:
   - set the affected `check_log` entries to `ok`, with a detail such as "headers observed in a browser session on <date>; collector was challenged";
   - add or remove findings using **only** what you actually observed, quoting the header as evidence;
   - remove the `unverified` entries you have now confirmed, and add a limitation naming the supplementary source.
4. Re-render: `python3 gen.py reports/<domain>-reviewed/findings.json --out reports/<domain>-reviewed --no-history`.

Use the same reviewed-copy method for other things the collector could not observe: port 80 blocked from the box (the detail says "not evidence about the target"), or crt.sh/RDAP outages.

## 6. Shared hosting targets (`*.netlify.app`, `*.vercel.app`, `*.github.io`, …)

For a site that lives *under* a shared platform suffix, the platform controls the DNS zone, DNSSEC, CAA, mail DNS, TLS and registry. The collector reports those items as `info` "Platform-level:" findings so they do not affect the grade, and it marks RDAP as not applicable. Headers, CSP and security.txt are still graded, because the site owner controls them. If the owner has a custom domain, assess that domain instead. It gives a much more useful report.

## 7. Updating

```bash
cd /workspace/scafu-grok-bot && git pull --ff-only && SCAFU_OFFLINE=1 bash run_tests.sh
```

`reports/`, `out/`, `.venv/` and generated PDFs/PNGs are git-ignored, so pulling never touches your reports.
