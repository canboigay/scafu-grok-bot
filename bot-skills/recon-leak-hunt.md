---
name: recon-leak-hunt
description: >-
  Passive leak hunt for an authorized organisation: search public code, packages,
  docs and the site's own public assets for exposed secrets, API keys, system
  prompts and configs. Redact everything; never use a found credential.
---
# Passive leak hunt (secrets, keys, prompts)

**Rules for the whole playbook:**
- Use public sources only and stay passive.
- Never log in with, test or "validate" a found key or token. Never call the service it belongs to.
- Redact every secret to its first 4 and last 4 characters in chat, files and reports.
- Do not guess paths on the target (no `/.env`, `/.git/`, backup-file or directory brute force) unless the owner explicitly put a short, named list of well-known paths in scope. Even then, make one GET per path and do not download repositories.

1. **Confirm scope.** You need the authorized organisation/domain, the authorized_by name, and which public footprints are in scope (code-hosting orgs, package names, docs sites, subdomains from the SCAFU CT list). Ask one question at a time. Anything you discover that is not on the list needs fresh authorization.
2. **Seed from what you already have.** Use `reports/<domain>/raw/` if it exists: the CT names, TXT records (verification tokens are normal, not leaks) and fingerprint. Create `reports/<domain>-leaks/` with an `evidence/` folder.
3. **Search public code.** If a code-hosting connector is available, use its code search. Otherwise use public web search. Search for the org name, domain and product names together with high-signal patterns:
   - `api_key`, `secret`, `token`, `password`, `BEGIN PRIVATE KEY`;
   - provider prefixes such as `sk-`, `sk-ant-`, `AKIA`, `ghp_`, `xox`, `AIza`;
   - `eyJ` (JWTs), `service_role`;
   - connection strings (`postgres://`, `mongodb+srv://`, `redis://`).

   Look in `.env`, `.env.example`, config, CI and notebook files in the org's **public** repositories.
4. **Check public packages.** Check the npm, PyPI and container-registry packages the org publishes. Read the package metadata and the file list. Grep the published source for the same patterns and for embedded prompts (`system prompt`, `You are`, prompt template folders).
5. **Read the site's own public assets.** GET the homepage and the docs pages the owner named, and the JS bundles they reference. Grep for keys, public config objects (`NEXT_PUBLIC_*`, `firebaseConfig`, Supabase anon keys, Sentry DSNs) and inline prompts. Note which values are *designed* to be public (publishable keys, anon keys protected by row-level security, analytics IDs) and grade them info unless there is evidence of misuse.
6. **Search paste sites and the web.** Search for the domain, the org name and its API-key variable names on paste sites, gists and issue trackers. Record what you searched even when nothing turns up.
7. **Classify each candidate.**
   - real secret (**medium/high**; recommend rotation);
   - placeholder/test value (not a finding);
   - intentionally public value (**info**);
   - third-party key in the org's code (**medium**; name the third party).

   Give each a confidence level. Save a redacted excerpt and the exact public URL or commit to `evidence/`.
8. **Write `REPORT.md`.** Include:
   - a verdict table (prompts / credentials / exposed data stores / other) with confidence;
   - numbered findings with evidence URL, redacted excerpt and recommendation;
   - an honest **"Checks that found nothing"** section;
   - a **blockers** section (WAF challenges, rate limits, private repos).

   Never paste a full secret.
9. **Deliver and offer next steps.** Give the owner the verdicts and the path to the report. If you found a live-looking secret, recommend rotating it at the provider now. Offer the other go-deeper options (tech stack, routes and forms) for the same target. Do not contact third parties or file reports on the owner's behalf without their explicit approval.
