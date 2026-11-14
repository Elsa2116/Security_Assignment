import { defineConfig } from '@playwright/test';

// Keep Playwright browser tests separate from the Vitest unit tests in tests/health.test.ts.
export default defineConfig({
  testDir: './tests/e2e',
  testMatch: '**/*.spec.ts',
  use: {
    baseURL: 'http://localhost:3000',
    headless: false,
    // Use the installed Chrome browser because Windows Application Control blocks Playwright's downloaded Chromium binary.
    channel: 'chrome',
  },
});
