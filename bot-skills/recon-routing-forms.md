---
name: recon-routing-forms
description: >-
  Map an authorized site's public routes, forms and API endpoints passively
  (sitemap, robots, links, JS route tables, public OpenAPI). Never submits a form
  or sends data unless the owner explicitly confirms that exact submission.
---
# Map routes and forms (stop before submit)

**Hard stop:** this is read-only. Do not submit, POST, sign up, log in, upload or trigger email/SMS flows. If a form looks worth testing, describe it and ask the owner. Only one exact submission (URL, fields, values), confirmed in chat by the owner for a site they control, may be sent, and it is sent once. Never brute-force paths, parameters or IDs.

1. **Confirm the target host(s) and authorized_by.** Hosts discovered along the way (from links, the CT list or JS) need the owner's confirmation before you request them.
2. **Collect the public route sources:**
   - `/robots.txt` and the sitemap(s) it lists, plus `/sitemap.xml`;
   - the homepage navigation and footer links;
   - `llms.txt` if published;
   - a public `openapi.json`/`swagger.json` *only if linked from public docs*.

   Keep the request rate low: about one request per second, with a cap the owner can see (default 100 pages).
3. **Mine the JavaScript.** Read the bundles the pages already load. Pull out route tables (for example Next.js `_buildManifest.js` and SPA router configs), `fetch`/axios base URLs and API path strings. Record them as *referenced*, not *verified*.
4. **Inventory the forms.** For each page with a `<form>` or a JS-driven form (sign-up, login, contact, newsletter, search, upload, checkout), record:
   - page URL, action URL and method;
   - field names and types;
   - CAPTCHA / bot protection present;
   - CSRF token present (a hidden field or header name only; never its value);
   - third-party handler (HubSpot, Formspree, Typeform, Stripe Checkout…).

   Do not fill in or submit anything.
5. **Note security-relevant observations, passively:**
   - forms posting to `http://`;
   - login/sign-up pages without visible bot protection;
   - admin/staging routes linked publicly;
   - API endpoints documented as unauthenticated;
   - verbose error pages seen during normal browsing.

   Each is an observation with evidence, not a confirmed vulnerability.
6. **If a WAF challenge blocks you,** stop automated fetching for that host. Offer to browse it in this bot's own browser as a normal visitor, read-only. Never bypass the challenge.
7. **Write `reports/<domain>-routes/REPORT.md`.** Include:
   - a route table (path, source, status if fetched, auth required yes/no/unknown);
   - a forms table;
   - an API endpoint list (documented vs. referenced in JS);
   - observations;
   - what you did not do (no submissions, no auth).
8. **Deliver and offer next steps.** Offer, as choices: confirm one specific form submission to test (the owner names the form and values), the leak hunt, the tech-stack map, or done.
