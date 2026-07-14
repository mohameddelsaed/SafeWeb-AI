import { Page, expect } from '@playwright/test';

export class DashboardPage {
  constructor(private page: Page) {}

  async mockDashboardStats() {
    await this.page.route('**/api/v1/dashboard/stats/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          stats: { total_scans: 10, total_vulnerabilities: 5 },
          recent_scans: []
        })
      });
    });
  }

  async verifyDashboardLoaded() {
    await this.page.waitForURL('**/dashboard*');
    await expect(this.page.locator('text=Security Dashboard')).toBeVisible();
  }

  async navigateToNewScan() {
    await this.page.click('text="New Scan"');
    await this.page.waitForSelector('input[name="target"]');
  }
}
