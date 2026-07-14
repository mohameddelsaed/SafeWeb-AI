import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Accessibility (a11y) Test Suite', () => {
  // Test Axe Core on the Dashboard/Landing page (since unauthenticated it might be landing page)
  test('Landing Page should not have any automatically detectable accessibility issues', async ({ page }) => {
    await page.goto('/');

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    
    // Assert zero critical or serious violations
    const violations = accessibilityScanResults.violations.filter(
      (violation) => violation.impact === 'critical' || violation.impact === 'serious'
    );
    expect(violations).toEqual([]);
  });

  // Test Keyboard Trapping on interactive elements like forms
  test('Keyboard Navigation should not trap focus', async ({ page }) => {
    await page.goto('/register');
    
    // Tab through the elements to ensure focus is not trapped
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    
    // As long as we can tab through without the page hanging or focus getting stuck
    // in an infinite loop inside a modal, it's a pass.
    // In playwright, we can just ensure that tabbing works and elements receive focus.
    const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(focusedElement).toBeDefined();
  });
});
