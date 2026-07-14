import { Page, expect } from '@playwright/test';

export class ReportPage {
  constructor(private page: Page) {}

  async mockScanReport(scanId: string) {
    await this.page.route(`**/api/v1/scan/${scanId}/`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: scanId,
          status: 'completed',
          target: { domain: 'example.com' },
          findings: []
        })
      });
    });
  }

  async navigateToReport(frontendUrl: string, scanId: string) {
    await this.mockScanReport(scanId);
    await this.page.goto(`${frontendUrl}/scan/results/${scanId}`);
    // Wait for a report element to be visible
    // Depending on frontend implementation, there could be a specific element,
    // For now we assume the scan ID route loads fine.
  }

  async downloadPDF() {
    // Intercept download event
    const downloadPromise = this.page.waitForEvent('download');
    
    // Attempt to click the "Export PDF" button
    // The exact text or locator depends on the UI implementation.
    // If it's a menu item, we might need to open the menu first.
    // Assuming there's a button with text "Export PDF" or similar
    await this.page.click('button:has-text("Export")');
    
    // Wait for the download to start
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');
  }
}
