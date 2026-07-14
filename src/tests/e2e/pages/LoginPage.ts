import { Page } from '@playwright/test';

export class LoginPage {
  constructor(private page: Page) {}

  async mockLoginApi(testUser: string) {
    await this.page.route('**/api/v1/auth/login/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tokens: { access: 'fake-token' },
          user: { id: 'uuid', email: testUser, username: testUser, has_targets: true, role: 'user' }
        })
      });
    });
  }

  async mockOrganizations() {
    await this.page.route('**/api/v1/user/organizations/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'org_id', name: 'Test Org', role: 'admin' }
        ])
      });
    });
  }

  async login(testUser: string, testPass: string, frontendUrl: string) {
    await this.mockLoginApi(testUser);
    await this.mockOrganizations();
    await this.page.goto(`${frontendUrl}/login`);
    await this.page.fill('input[id="email-address"]', testUser);
    await this.page.fill('input[id="password"]', testPass);
    await this.page.click('button[type="submit"]');
  }
}
