---
name: recon-tech-stack
description: >-
  Passive technology-stack map for an authorized domain: hosting, CDN, DNS, TLS,
  framework, CMS, analytics, email, auth and payments, each with evidence and a
  confidence level. No version-based CVE claims without the inferred label.
---
# Passive tech-stack map

1. **Confirm the target and authorized_by.** Ask one question at a time if either is missing. Reuse `reports/<domain>/raw/` from the SCAFU run when it exists, and run **run-scafu-passive-report** first if it doesn't.
2. **Infrastructure from the raw data:**
   - DNS: A/AAAA owners, CNAME targets, NS provider, MX provider;
   - TXT verification tokens: these name the SaaS products in use;
   - TLS issuer and SANs;
   - CT host list (from `raw/ct.json`): group hosts by role, e.g. app, api, docs, status, staging.
3. **Edge and hosting from headers.** Use the `server`, `via`, `x-powered-by`, `x-vercel-*`, `cf-ray`, `x-amz-cf-*`, `x-nf-*`, `fly-request-id` and `x-served-by` headers from the GET of `/`. If the GET was a bot-challenge, the platform is still visible, but the page itself was not observed. Say so, and offer a browser check.
4. **Front end from the HTML.** Make one GET of the homepage plus the main docs/app landing page (only hosts in scope). Look for:
   - framework markers: `/_next/`, `__NUXT__`, `data-astro-*`, `ng-version`, `wp-content`, `generator` meta;
   - CMS/CDN asset hosts (e.g. `cdn.sanity.io`, `images.ctfassets.net`);
   - analytics/tag managers;
   - chat widgets;
   - auth providers (Auth0, Clerk, Cognito, Supabase, Firebase);
   - payment scripts (Stripe, Paddle).
5. **Public product footprint.** Check the public SDKs and packages (npm/PyPI), the public code org, and the docs platform (Mintlify, GitBook, Docusaurus). Link each one.
6. **Write a table.** Columns: area, finding, confidence (high = direct header/DNS evidence, medium = strong marker, low = indirect), evidence file or URL. Save raw snippets under `reports/<domain>-stack/evidence/`.
7. **No guessed vulnerabilities.** If you mention a version, any CVE match is `inferred` and labelled POTENTIAL, at medium severity or below. Do not probe to confirm it.
8. **Deliver** `reports/<domain>-stack/REPORT.md` with a short summary, then offer the other go-deeper options (leak hunt, routes and forms, browser header check if a WAF blocked the collector).
