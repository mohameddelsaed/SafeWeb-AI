---
Source agent: Repository Analysis Agent
Run date: 2026-06-23
Inputs used: Full clone of safeweb-ai, SAFEWEB_AI_CODEBASE_BOOK.md
Status: draft
---

# Dead or Orphaned Code

1. `backend/apps/ml/` (High Confidence)
   - Reason: ML modules for phishing and malware detection exist as preserved artifacts, but current web application scanning paths bypass them.

2. Extraneous testing scripts and logs (High Confidence)
   - Paths: `backend/test_final_v3.txt`, `backend/test_gap_fixes.txt`, `api_test_out.txt`, `scan_live_err.txt`, `backend/check_status.py`, `django_server_err.txt`
   - Reason: Scratchpad and output logs committed to the root and backend directories with no system components depending on them.

3. `presentation_old.html` (High Confidence)
   - Reason: Superceded or unused asset left in the root directory.
