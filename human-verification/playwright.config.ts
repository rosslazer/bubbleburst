import { defineConfig } from '@playwright/test';

// The end-to-end suite drives a real Chromium with a CDP virtual authenticator (software, negative control).
// The pre-installed browser path is used when Playwright's own download is unavailable.
const executablePath = process.env.HV_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: 'test/e2e',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.HV_E2E_BASE_URL || 'http://localhost:8797',
    headless: true,
    launchOptions: executablePath ? { executablePath } : {},
  },
  webServer: {
    command: 'HV_PORT=8797 HV_ORIGIN=http://localhost:8797 HV_RP_ID=localhost HV_DB_PATH=:memory: HV_MDS_FETCH=false npx tsx src/server.ts',
    url: 'http://localhost:8797/healthz',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
