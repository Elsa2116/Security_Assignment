import { test, expect } from '@playwright/test';

// Confirm the real browser can open the SecureFlow registration page and find its primary controls.
test('SecureFlow registration page loads', async ({ page }) => {
  await page.goto('/');
  // The application defaults unauthenticated visitors to sign-in; explicitly open registration for this test.
  await page.getByRole('link', { name: 'Create an account' }).click();
  await expect(page.getByRole('heading', { name: 'Create your account' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible();
});
