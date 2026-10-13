# scafu-grok-bot · Surface Check report generator

**Powered by SCAFU · [sca-fu.com](https://sca-fu.com)**

This tool turns the results of a **passive** external security check (DNS, registry, Certificate Transparency, TLS and ordinary public HTTP responses) into a branded consultancy-style report: `report.html`, a print-quality `report.pdf`, and two PNG previews. The report is built from a single `findings.json`:

- a cover page and an executive summary with an A–F grade calculated by a documented rubric;
- severity counts, priority actions and a findings table;
- one card per finding, plus strengths, unverified items, an assessment-coverage table and raw-record appendices;
- an optional "Changes since last assessment" section, based on dated history snapshots.

Sections appear only when there is data for them. It works with anything from 0 to 40+ findings, and every font and image is embedded (no external loads).

> ### ⚠️ Authorized, passive use only
> Only use this on targets **you own or are explicitly authorized in writing to assess**. The workflow it is designed for is **passive and non-intrusive** (public DNS/RDAP/CT lookups, single TLS handshakes, ordinary GET/HEAD requests to public pages). It is not for brute force, port scanning, exploitation or authenticated testing. Findings inferred from version strings or fingerprints (for example CVE matches) are required to be marked `basis: "inferred"`, are labelled **POTENTIAL** and are capped at medium severity.

## Setup

- **Python 3.9+** (the generator and validator use only the standard library)
- **Headless Chromium or Google Chrome** (`chromium`, `chromium-browser`, `google-chrome` or `google-chrome-stable` on `PATH`) for the PDF
- **poppler-utils** (`pdftoppm`, `pdfinfo`) for the PNG previews and page count
- **pytest**, only for the tests. `bash run_tests.sh` creates a local `.venv` and installs it (`pip install pytest`).

```bash
# Debian/Ubuntu example
sudo apt install python3 python3-venv chromium poppler-utils
git clone https://github.com/canboigay/scafu-grok-bot && cd scafu-grok-bot
bash run_tests.sh        # or: chmod +x run_tests.sh && ./run_tests.sh
```

## Usage

```bash
python3 gen.py examples/hypothetical-critical.json --out out/            # HTML + PDF + previews
python3 gen.py findings.json --out out/ --no-pdf                         # HTML only
python3 gen.py findings.json --out out/ --history-dir path/to/history    # choose the snapshot folder
python3 gen.py findings.json --out out/ --no-history                     # do not read or write snapshots
python3 gen.py findings.json --out out/ --auto-cap                       # cap inferred critical/high findings to medium
python3 validate.py findings.json                                        # validate only (gen.py does this automatically)
bash run_tests.sh                                                        # test suite
```

- Output: `<out>/report.html`, `report.pdf`, `preview-1.png` (cover) and `preview-2.png` (executive summary).
- History: each run saves `<history-dir>/<date>_<time>.json`. The default is `$SCAFU_REPORTS_DIR/<target>/history/`, and `SCAFU_REPORTS_DIR` defaults to `reports/` in this folder (git-ignored).
- Invalid input: the program prints one `error:` line per problem and exits with status 1 without rendering.

## Schema, rubric and branding

See **[schema.md](schema.md)** for the full `findings.json` schema, the grading rubric, the CVE/inferred rule, the check log, history and the `brand` block.

Grading rubric: `score = 100 − (40×critical + 15×high + 5×medium + 1×low)`. A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, otherwise F. Caps: any high → at best C, one critical → at best D, two or more critical → F.

Branding defaults are in [`brand.json`](brand.json) (SCAFU: `#0b0a09` / ivory `#f3ede4` / champagne `#c4b59a`, with Newsreader + Inter type). Override any part with a `brand` block in `findings.json`, or set `"powered_by": false` to hide the line.

## Examples

Everything in `examples/` is **EXAMPLE DATA**: hypothetical `.test` targets and fictional findings, plus the empty and 45-finding stress files used for testing. No real assessment data is included.

## Layout

```
gen.py            report generator (paths are relative to this folder)
validate.py       schema validator
style.css         report design
brand.json        default SCAFU brand
schema.md         schema + rubric documentation
build/*.b64       embedded fonts (base64 text), licences in build/licenses/
examples/         EXAMPLE DATA inputs
tests/            pytest suite; run_tests.sh runs it
```

## Licence

- Code (`gen.py`, `validate.py`, `style.css`, tests, scripts and docs) is under the **MIT licence**, see [LICENSE](LICENSE).
- The fonts in `build/` (Inter, JetBrains Mono, Newsreader) are under the **SIL Open Font License 1.1**, see [build/licenses/](build/licenses/). They are stored as base64-encoded WOFF/WOFF2 so the repository stays text-only.
- "SCAFU" and the SCAFU brand belong to their owner and are not covered by the MIT licence.
