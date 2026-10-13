# SCAFU Recon report generator (default brand: SCAFU)

```
python3 gen.py findings.json --out <dir> [--no-pdf] [--history-dir DIR | --no-history] [--auto-cap]
python3 validate.py findings.json      # validation only; gen.py runs it automatically
./run_tests.sh                          # pytest suite (creates .venv with pytest on first run)
```
- gen.py validates first and exits 1 (one `error:` line per problem on stderr) without rendering if the file is invalid.
- `--history-dir` default: `$SCAFU_REPORTS_DIR/<target>/history/`; `SCAFU_REPORTS_DIR` defaults to `reports/` next to `gen.py`. `--no-history` neither reads nor writes snapshots.
- `--auto-cap` downgrades inferred critical/high findings to medium (recording `claimed_severity`) instead of failing.
Writes `<dir>/report.html`, `report.pdf` (headless Chrome/Chromium), `preview-1.png` (cover), `preview-2.png` (executive summary).
Needs `style.css` and `build/inter.woff`, `build/mono.woff` next to `gen.py`, plus Chrome/Chromium and poppler (`pdftoppm`, `pdfinfo`).

## findings.json

| Field | Type | Req. | Notes |
|---|---|---|---|
| `target` | string | yes | Domain; shown on cover and page headers |
| `date` | `YYYY-MM-DD` | no | Assessment date (PT). Default: today |
| `authorized_by` | string | no | e.g. "Domain owner (Jane Doe)" |
| `scope` | string or string[] | no | Default: target |
| `methods` | string[] | no | "Sources & techniques" box |
| `out_of_scope` | string[] | no | Default: brute force, port scanning, exploitation, authenticated testing |
| `findings` | object[] | no | See below. May be empty |
| `strengths` | (string or `{title, detail}`)[] | no | Section omitted when empty |
| `unverified` | `{item, reason, confirm?}`[] | no | Omitted when empty (together with `limitations`) |
| `limitations` | string[] | no | General limitations list |
| `check_log` | `{check, status: ok\|failed\|skipped, detail}`[] | no | "Assessment coverage" table in the limitations section; failed/skipped listed first and mentioned in the exec-summary note |
| `appendix` | `{title, type, content, note?, break?}`[] | no | Omitted when empty |
| `grade` | `A`–`F` | no | Overrides the rubric (rubric result is still shown as a note) |
| `tagline` | string | no | Overrides the grade tagline |
| `summary` | string or string[] | no | Overrides the auto-written verdict paragraphs |
| `prepared_by`, `version`, `assessment_type` | string | no | Defaults: "SCAFU Recon", "1.0", passive |
| `brand` | object | no | Overrides keys of `brand.json` (deep-merged); see Branding |
| `example` | bool | no | `true` marks every page EXAMPLE DATA (cover flag, banner, footer) |

### Finding
`{ id?, key?, severity, title, description, evidence, impact, remediation[], status?, action?, basis?, confidence?, claimed_severity?, cve? }`
- `key`: stable identity used to match findings between runs (history). Default: slug of the title, e.g. `no-hsts-strict-transport-security-header`. Set it explicitly if a title's wording may change. Must be unique.
- `basis`: `observed` (default) or `inferred`. `confidence`: `high|medium|low` or a number 0–1 (shown on the card).
- `cve`: string or list. Unknown fields are rejected.
- `severity`: `critical | high | medium | low | info` (case-insensitive).
- `id` optional: auto-numbered per severity in input order — `C-01`, `H-01`, `M-01`, `L-01`, `I-01` (given ids are kept and skipped).
- Findings are sorted by severity. Empty description/evidence/impact/remediation rows are hidden.
- `status`: free text. Default "Open" (Observation for info). Anything containing "unverified" gets the amber tag.
- `action`: short label for the Priority actions list; default = first sentence of the first remediation step (≤60 chars).
- Evidence is monospace, pre-wrapped and breaks anywhere, so long tokens never overflow.

### CVE / inferred rule
Any finding derived from a version string or fingerprint → CVE match **must** be `basis: "inferred"` (validation rejects a `cve` on an observed finding).
- Inferred findings may be at most **medium**. A critical/high inferred finding is a validation error; put the database rating in `claimed_severity` and set `severity` ≤ medium (or use `--auto-cap`).
- The generator always labels them **POTENTIAL** (findings table and card), forces status **Unverified** (shown in the table's Status column and on the card), and adds a Basis row: inferred, CVE ids, "Claimed severity X, capped at Y", confidence.
- The renderer also caps defensively if validation is bypassed.

### Appendix item types
- `records`: `content` is `{key: value}` or `[[key, value], …]` → key/value table.
- `table`: `content` = `{columns: [], rows: [[]], widths?: ["30%", …, null]}`; a list cell becomes line breaks.
- `raw`: `content` string (or any JSON, pretty-printed) → monospace block.
Each item starts a new page unless `"break": false`.

## Adaptive behaviour
- Count cards always show all 5 severities (zeros greyed).
- Severity groups with no findings are omitted; 0 findings shows a "no findings" panel.
- Priority actions: up to 3 findings of the highest non-info severity present, topped up from the next severities; none → "No remediation is required".
- The note under priorities and section numbers adapt to whether strengths/limitations exist.
- Verdict paragraphs and tagline are generated from the grade, counts, top findings and strengths unless overridden.

## Branding
Defaults live in `brand.json` (SCAFU, taken from https://sca-fu.com). A findings file can override any key with a `brand` block, which is deep-merged, so you can change only one colour.
```json
"brand": {
  "name": "SCAFU", "url": "https://sca-fu.com", "eyebrow": "Forensic Security Consulting",
  "wordmark": {"text": "SCAF", "accent": "U"},        // typographic wordmark, used when there is no logo
  "logo": null,                                        // local .svg/.png/.jpg/.webp, relative to the findings file or template; embedded as data URI
  "colors": {"dark": "#0b0a09", "dark_deep": "#060605", "on_dark": "#f3ede4",
             "accent": "#c4b59a", "accent_text": "#7a6a4f", "ink": "#1a1816"},
  "powered_by": {"text": "Powered by SCAFU · sca-fu.com", "url": "https://sca-fu.com"}   // or a string, or false to hide it
}
```
- `dark` is used for the cover, the grade badge and headings, and `on_dark` for text on dark areas. `accent` is the cover/badge highlight; `accent_text` is a darker accent that stays readable on white paper (section numbers, priority actions). `ink` is body text.
- The powered-by line appears on the cover and the end line (both linked), in every PDF page footer (centre), and in a linked footer under every section in the HTML screen view. Chrome cannot put links in PDF page margins, so the per-page PDF footer is plain text.
- The severity colours are fixed and do not follow the brand, so their meaning stays the same.
- Fonts: Inter (body), Newsreader (headings and grade letter) and JetBrains Mono (evidence) are all embedded from `build/`. The report makes no external requests apart from the brand links.

## History
Each successful run saves the input (plus `_snapshot: {saved_at, grade}`) as `<history-dir>/<date>_<HHMMSS>.json`. If a snapshot already exists, the newest one is compared with the current run by finding `key`, and a **Changes Since Last Assessment** section (after the Findings Summary) shows the grade delta (previous → current, improved/declined/unchanged), new findings, resolved findings and severity changes, plus an unchanged count. The first run has no section. Root fields starting with `_` are ignored by validation.

## Grading rubric
```
score = 100 − (40 × critical + 15 × high + 5 × medium + 1 × low)      (info = 0)
A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40
Caps: any high → at best C · exactly one critical → at best D · two or more critical → F
```
Taglines: A "Strong posture, minor polish only" · B "Good, with hardening gaps" · C "Fair, several gaps to address" · D "Weak, significant risks present" · F "Poor, urgent remediation required".

## Examples
- `examples/hypothetical-critical.json` – EXAMPLE DATA: critical/high findings, no strengths, long evidence (score 19 → F); includes an inferred nginx CVE finding (claimed high, capped medium) and a failed check.
- `examples/hypothetical-critical-followup.json` – EXAMPLE DATA: a later run of the above, used to show the Changes section (render with `--history-dir` pointing at the first run's history).
- `examples/stress-zero-findings.json`, `examples/stress-45-findings.json` – edge-case tests.
