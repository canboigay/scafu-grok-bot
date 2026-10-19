#!/usr/bin/env bash
# One-command passive assessment: collect -> validate -> render.
# Usage: ./scafu.sh <domain> [--out DIR] [--authorized-by NAME] [--allow-incomplete] [--no-pdf] [--no-history] [--history-dir DIR]
# Only run against domains you own or are explicitly authorized to assess. Everything is passive.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ $# -ge 1 ] || { sed -n '2,4p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
DOMAIN="$1"; shift
OUT=""; AUTH=""; VALFLAGS=(); GENFLAGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --authorized-by) AUTH="$2"; shift 2 ;;
    --allow-incomplete) VALFLAGS+=(--allow-incomplete); GENFLAGS+=(--allow-incomplete); shift ;;
    --no-pdf|--no-history|--auto-cap) GENFLAGS+=("$1"); shift ;;
    --history-dir) GENFLAGS+=(--history-dir "$2"); shift 2 ;;
    *) echo "error: unknown option $1" >&2; exit 2 ;;
  esac
done
OUT="${OUT:-${SCAFU_REPORTS_DIR:-$HERE/reports}/$DOMAIN}"
echo "==> [1/3] collect  $DOMAIN  ->  $OUT" >&2
COLLECT=(python3 "$HERE/collect.py" "$DOMAIN" --out "$OUT"); [ -n "$AUTH" ] && COLLECT+=(--authorized-by "$AUTH")
"${COLLECT[@]}" >/dev/null || { echo "collect failed" >&2; exit 1; }
echo "==> [2/3] validate" >&2
python3 "$HERE/validate.py" "$OUT/findings.json" "${VALFLAGS[@]}" || { echo "validation failed; fix $OUT/findings.json or pass --allow-incomplete" >&2; exit 1; }
echo "==> [3/3] render" >&2
SUMMARY=$(python3 "$HERE/gen.py" "$OUT/findings.json" --out "$OUT" "${GENFLAGS[@]}") || exit 1
python3 - "$OUT/findings.json" "$SUMMARY" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); s = sys.argv[2]
bad = [c for c in d["check_log"] if c["status"] != "ok"]
print("\n" + "=" * 64)
print(f" {d['target']}  |  {s.split(' | ')[0]}  |  " + " ".join(x for x in s.split(" | ")[1].split()))
print(f" Findings {len(d['findings'])} · strengths {len(d['strengths'])} · checks {len(d['check_log'])} ({len(bad)} failed/skipped)")
for c in bad: print(f"   - {c['status'].upper():7} {c['id']}: {c['detail'][:90]}")
print(" Report: " + s.split(" | ")[3] + "/report.html  (+ report.pdf, preview-1.png, preview-2.png)")
if any("bot-challenge" in c["detail"] for c in bad):
    print(" ! A bot-challenge/WAF page answered some HTTP checks. Those items are UNVERIFIED, not findings.")
    print("   Capture headers from a normal browser session and make a reviewed copy (see INSTALL.md).")
if any("not evidence about the target" in c["detail"] for c in bad):
    print(" ! Outbound port 80 looks blocked from this machine; the HTTP->HTTPS redirect was not tested.")
if "NOT CONFIRMED" in d.get("authorized_by", ""):
    print(" ! authorized_by is not set. Re-run with --authorized-by \"Name (role)\" before sharing.")
print(" Review the draft findings and authorized_by before sharing.")
print("=" * 64)
PY
