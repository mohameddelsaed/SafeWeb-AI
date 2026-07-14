import { test } from '@playwright/test';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { ScanPage } from './pages/ScanPage';
import { ReportPage } from './pages/ReportPage';

test.describe('SafeWeb AI User Journeys (POM)', () => {
  const testUser = 'testuser@example.com';
  const testPass = 'Password123!';
  const frontendUrl = 'http://localhost:5173';

  test('User Onboarding Flow', async ({ page }) => {
    const loginPage = new LoginPage(page);
    const dashboardPage = new DashboardPage(page);

    await dashboardPage.mockDashboardStats();
    await loginPage.login(testUser, testPass, frontendUrl);
    
    // Assert Dashboard loaded
    await dashboardPage.verifyDashboardLoaded();
  });

  test('Start Scan Flow', async ({ page }) => {
    const loginPage = new LoginPage(page);
    const dashboardPage = new DashboardPage(page);
    const scanPage = new ScanPage(page);

    await dashboardPage.mockDashboardStats();
    await loginPage.login(testUser, testPass, frontendUrl);
    await dashboardPage.verifyDashboardLoaded();

    await dashboardPage.navigateToNewScan();
    
    const mockScanId = 'mock-scan-id-123';
    await scanPage.startScan('https://example.com', mockScanId);
    
    await scanPage.verifySSEProgress();
  });

  test('Report Generation Flow', async ({ page }) => {
    const reportPage = new ReportPage(page);
    const mockScanId = 'mock-scan-id-123';
    
    await reportPage.navigateToReport(frontendUrl, mockScanId);
    
    // We would uncomment this when we know the exact UI layout for exporting PDF
    // await reportPage.downloadPDF();
  });
});
