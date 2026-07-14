# 09 - Regression Test Suite

## Objective
Ensure previously fixed bugs never resurface.

## Scope
- Bugfix #22: 404 on Scan Report Export.
- Bugfix #45: JWT Signature missing from SSE connections.
- Bugfix #89: Missing CSRF tokens on Contact Form.

## Specifications
1. **SSE JWT Token**:
   - Establish SSE connection passing JWT in query string `?token=...`.
   - Assert connection accepts and streams data.
2. **Export Report**:
   - GET `/api/v1/scan/{id}/export/?export_format=pdf`.
   - Assert 200 OK and `application/pdf` MIME type.

## AI Prompt Instructions
"Add these tests to a dedicated `test_regressions.py` file. Each test MUST have a docstring referencing the bug it is preventing."\n