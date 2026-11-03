import { clickTestId } from "../../shared";
import { expect } from "@playwright/test";
import {
  totpCode,
  totpSecretFromManualLocator,
} from "./totp";

export type EnrolledTotp = {
  secret: string;
  recoveryCodes: string[];
};

/**
 * Click Set up until the Scan step shows. A click made before the page
 * hydrates is dropped, so retry while the idle step is still showing.
 */
export async function startTotpSetup(
  page: import("@playwright/test").Page,
): Promise<void> {
  const scan = page.getByTestId("totp-settings-scan");
  await expect(async () => {
    if (await page.getByTestId("totp-settings-idle").isVisible()) {
      await clickTestId(page, "totp-settings-setup");
    }
    await expect(scan).toBeVisible({ timeout: 10_000 });
  }).toPass({ timeout: 60_000 });
}

/** Idle → Scan → Confirm → Recovery ack → Enabled. Caller must be on account-settings. */
export async function enrollTotpToEnabled(
  page: import("@playwright/test").Page,
): Promise<EnrolledTotp> {
  await expect(page.getByTestId("totp-settings-idle")).toBeVisible();
  await startTotpSetup(page);
  const secret = await totpSecretFromManualLocator(
    page.getByTestId("totp-settings-manual-secret"),
  );

  await clickTestId(page, "totp-settings-continue");
  await expect(page.getByTestId("totp-settings-confirm")).toBeVisible();
  await page.getByTestId("totp-settings-code").fill(await totpCode(secret));
  await clickTestId(page, "totp-settings-confirm-submit");

  await expect(page.getByTestId("totp-settings-recovery")).toBeVisible({
    timeout: 30_000,
  });
  const recoveryText = await page
    .getByTestId("totp-settings-recovery-list")
    .innerText();
  const recoveryCodes = recoveryText
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
  expect(recoveryCodes.length).toBe(8);

  await page
    .getByTestId("totp-settings-recovery-ack")
    .locator('input[type="checkbox"]')
    .check();
  await clickTestId(page, "totp-settings-recovery-done");
  await expect(page.getByTestId("totp-settings-enabled")).toBeVisible({
    timeout: 30_000,
  });

  return { secret, recoveryCodes };
}

export function parseRecoveryCodes(text: string): string[] {
  return text
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
