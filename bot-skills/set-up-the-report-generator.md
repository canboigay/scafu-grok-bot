---
name: set-up-the-report-generator
description: >-
  Install the SCAFU passive Surface Check report pipeline on this box: clone it to
  /workspace/scafu-grok-bot, install openssl/dig/Chrome/poppler as needed, make the
  scripts executable and pass the offline test suite before any scan.
---
# Set up the report generator

Use this on a fresh box, when `/workspace/scafu-grok-bot` is missing, or when a report run fails with a missing tool. You need no keys or accounts.

1. **Check what exists.** Run `ls /workspace/scafu-grok-bot/scafu.sh`. If the file is there, run `git -C /workspace/scafu-grok-bot pull --ff-only`. If it isn't, run `cd /workspace && git clone https://github.com/canboigay/scafu-grok-bot`.
2. **Make the scripts executable.** Run `chmod +x /workspace/scafu-grok-bot/scafu.sh /workspace/scafu-grok-bot/run_tests.sh`. A GitHub-API or zip download loses the executable bit.
3. **Find missing tools.** Look for each of these on `PATH`: `python3` (3.9+, with `venv`), `openssl`, `dig`, `pdftoppm`, `pdfinfo`, and one of `chromium`, `chromium-browser`, `google-chrome` or `google-chrome-stable`.
4. **Install only what is missing.** On Debian/Ubuntu run `sudo apt-get update && sudo apt-get install -y python3 python3-venv openssl dnsutils poppler-utils chromium publicsuffix`, listing only the packages you need. If the box can't install Chrome/Chromium, tell the owner that reports will be HTML only (`--no-pdf`).
5. **Run the offline tests.** Run `cd /workspace/scafu-grok-bot && SCAFU_OFFLINE=1 bash run_tests.sh`. It should end with every test passing and 1 skipped (the live test). If anything fails, show the owner the failing test names and the error. Do not scan until the tests pass.
6. **Run the smoke test.** Run `bash scafu.sh example.com --out /tmp/scafu-smoke --no-history` (example.com is the IANA example domain). Check that `report.html` exists, and `report.pdf` too if Chrome is installed.
7. **Report setup status.** Tell the owner which tools were present, which you installed, the test result and the smoke-test grade. Note any environment limits the summary printed, for example "outbound port 80 looks blocked from this machine" (the HTTP→HTTPS redirect cannot be tested from here).
8. **Never** add API keys, tokens or private endpoints to the repository or to the skill. The pipeline only uses public sources.
