import { defineConfig, devices } from "@playwright/test";

const headed = !!process.env.PW_HEADED;

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  // One retry absorbs occasional hydration/timing flakes on GHA.
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3120",
    actionTimeout: 15_000,
    navigationTimeout: 24_000,
    ...devices["Desktop Chrome"],
    // Patreon capture: set PW_VIDEO=1 (and optionally PW_SLOW_MO) for WebM under test-results/.
    ...(process.env.PW_VIDEO
      ? {
          video: "on" as const,
          launchOptions: {
            slowMo: Number(process.env.PW_SLOW_MO ?? 300),
          },
        }
      : {}),
    ...(headed
      ? {
          launchOptions: {
            slowMo: Number(process.env.PW_SLOW_MO ?? 250),
          },
        }
      : {}),
  },
});
