import { test, expect } from '@playwright/test';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';

test.describe('Security Tests', () => {
  const testUser = 'testuser@example.com';
  const testPass = 'Password123!';
  const frontendUrl = 'http://localhost:5173';

  test('Stored XSS in Target Name - Dashboard rendering', async ({ page }) => {
    const loginPage = new LoginPage(page);
    const dashboardPage = new DashboardPage(page);

    const xssPayload = '<script>alert(1)</script>';

    // We intercept any javascript dialogues (alerts)
    let alertTriggered = false;
    page.on('dialog', dialog => {
      alertTriggered = true;
      dialog.dismiss();
    });

    await loginPage.login(testUser, testPass, frontendUrl);
    await dashboardPage.verifyDashboardLoaded();

    // Go to Scans and start a new scan with the payload
    await page.getByText('New Scan').click();
    
    // The target input
    await page.fill('input[name="target"]', xssPayload);
    await page.click('button[type="submit"]');

    // Wait for the API response which should block it or accept it safely
    // We don't care if it's 400 or 200, we just want to ensure NO alert is triggered
    // Let's just go back to Dashboard
    await page.goto(`${frontendUrl}/dashboard`);
    await dashboardPage.verifyDashboardLoaded();

    // Verify no alert was triggered
    expect(alertTriggered).toBeFalsy();
  });
});
