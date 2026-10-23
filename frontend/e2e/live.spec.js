import { test, expect } from '@playwright/test';

test('analyst can investigate suspicious uploaded logs through the browser', async ({ page }) => {
  const attackIp = '198.51.100.77';
  const timestamp = new Date().toISOString();
  const events = Array.from({ length: 6 }, (_, index) => JSON.stringify({
    timestamp,
    source_ip: attackIp,
    event_type: 'LOGIN_FAILED',
    severity: 'HIGH',
    message: `Browser E2E failed login ${index + 1}`,
    username: 'browser-e2e',
  })).join('\n');

  await page.goto('/');
  await page.locator('#login-username').fill(process.env.ADMIN_USERNAME);
  await page.locator('#login-password').fill(process.env.ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Enter workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Your security overview' })).toBeVisible();

  await page.getByRole('button', { name: 'Log explorer' }).click();
  await page.getByRole('button', { name: 'Upload Log File' }).click();
  await page.locator('input[type="file"]').setInputFiles({
    name: 'browser-attack.jsonl',
    mimeType: 'application/x-ndjson',
    buffer: Buffer.from(events),
  });
  await page.getByRole('button', { name: 'Upload & Ingest' }).click();
  await expect(page.getByText('6 inserted, 0 rejected.')).toBeVisible();
  await page.getByRole('button', { name: 'Close' }).click();

  await page.getByPlaceholder('e.g. 198.51.100.10').first().fill(attackIp);
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.locator('tbody tr')).toHaveCount(6);

  await page.getByRole('button', { name: 'Detection rules' }).click();
  await page.getByRole('button', { name: 'Trigger Detection Scan' }).click();
  await expect(page.getByText('New Alerts Created: 1')).toBeVisible();

  await page.getByRole('button', { name: 'Threats & alerts' }).click();
  const alertRow = page.locator('tbody tr').filter({ hasText: attackIp }).first();
  await expect(alertRow).toBeVisible();
  await alertRow.getByRole('button', { name: 'Escalate' }).click();
  await expect(page.getByRole('heading', { name: 'Investigations' })).toBeVisible();
  await expect(page.getByText('Linked to Originating Alert')).toBeVisible();
  await page.getByRole('button', { name: 'Create Incident' }).click();
  await expect(page.getByText('Correlated Security Alerts (1)')).toBeVisible();

  await page.getByPlaceholder('Describe forensic finding, containment step executed, or response action...')
    .fill('Browser E2E triage completed');
  await page.getByRole('button', { name: 'Log Response Action' }).click();
  await expect(page.getByText('Browser E2E triage completed')).toBeVisible();

  await page.getByRole('button', { name: 'Overview' }).click();
  await expect(page.getByRole('heading', { name: 'Your security overview' })).toBeVisible();
});
