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

/** Idle → Scan → Confirm → Recovery ack → Enabled. Caller must be on account-settings. */
export async function enrollTotpToEnabled(
  page: import("@playwright/test").Page,
): Promise<EnrolledTotp> {
  await expect(page.getByTestId("totp-settings-idle")).toBeVisible();
  await clickTestId(page, "totp-settings-setup");
  await expect(
    page
      .getByTestId("totp-settings-scan")
      .or(page.getByTestId("totp-settings-error")),
  ).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("totp-settings-scan")).toBeVisible();
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
