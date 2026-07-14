# 10 - Accessibility Test Suite (a11y)

## Objective
Ensure SafeWeb AI UI meets WCAG 2.1 AA standards.

## Scope
- Color Contrast
- Screen Reader Labels (ARIA)
- Keyboard Navigation

## Specifications
1. **Axe Core Injection**:
   - Run `@axe-core/playwright` across Dashboard, Scan Details, and Reports.
   - Assert zero critical or serious violations.
2. **Keyboard Trapping**:
   - Tab through the `Onboarding` wizard. Assert focus is never trapped.

## AI Prompt Instructions
"Integrate `axe-core` into the Playwright E2E suite. Write tests that tab through interactive elements and assert focus states."\n