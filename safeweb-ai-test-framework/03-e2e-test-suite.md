# 03 - End-to-End (E2E) Test Suite Specification

## Objective
Validate the complete user journey from the browser using Playwright.

## Scope
- User Onboarding Flow
- Dashboard Metrics Loading
- Starting a Scan via UI
- Viewing a Scan Report

## Specifications & Assertions
1. **Onboarding Guard**:
   - Create a fresh user. Navigate to `/dashboard`.
   - Assert URL redirects to `/onboarding`.
   - Complete wizard. Assert redirect to `/dashboard`.
2. **Start Scan Flow**:
   - Navigate to `/scan/new`.
   - Fill target `https://example.com`. Select `Custom` depth. Click Start.
   - Assert navigation to `/scan/[id]`.
   - Assert Server-Sent Events (SSE) update the UI progress bar.
3. **Report Generation**:
   - Navigate to a completed scan.
   - Click "Export PDF". Assert file download initiates.

## AI Prompt Instructions
"Write Playwright tests in TypeScript under `src/tests/e2e/`. Use the Page Object Model (POM) pattern. Ensure tests wait for specific network responses rather than arbitrary timeouts."\n