import { defineConfig } from '@playwright/test';

// Ports are configurable so the suite can run while another service holds 8000 or 5173.
const apiPort = process.env.API_PORT || '8000';
const webPort = process.env.WEB_PORT || '5173';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    browserName: 'chromium',
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: `python -m uvicorn app.main:app --host 127.0.0.1 --port ${apiPort}`,
      cwd: '..',
      url: `http://127.0.0.1:${apiPort}/health`,
      timeout: 60_000,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: `npm run dev -- --host 127.0.0.1 --port ${webPort} --strictPort`,
      url: `http://127.0.0.1:${webPort}`,
      env: { API_TARGET: `http://127.0.0.1:${apiPort}` },
      timeout: 60_000,
      reuseExistingServer: !process.env.CI,
    },
  ],
});
