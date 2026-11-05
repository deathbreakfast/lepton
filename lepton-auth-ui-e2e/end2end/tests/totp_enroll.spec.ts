import {
  test,
  expect,
  authDialog,
  clickTestId,
} from "./fixtures";
import { totpCode, totpSecretFromManualLocator } from "./helpers/totp";
import {
  enrollTotpToEnabled,
  startTotpSetup,
  parseRecoveryCodes,
} from "./helpers/totp_settings";

async function gotoAccountSettingsSignedIn(
  page: import("@playwright/test").Page,
  auth: {
    signIn: (opts: {
      email: string;
      password: string;
      referer?: string;
    }) => Promise<void>;
  },
  email: string,
  password: string,
) {
  await auth.signIn({ email, password, referer: "/welcome" });
  await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
  await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  await page.goto("/user/account-settings");
  await expect(page.getByTestId("account-settings-container")).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.getByTestId("totp-settings-section")).toBeVisible();
}

async function logout(page: import("@playwright/test").Page) {
  await page.goto("/auth/logout");
  await expect(page.getByTestId("logout-container")).toBeVisible({
    timeout: 60_000,
  });
  await authDialog(page)
    .getByTestId("logout-button")
    .getByRole("button")
    .click();
  await expect(page).toHaveURL(/\/auth\/signin|\/$/, { timeout: 60_000 });
}

async function fillPasswordSignIn(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
) {
  await page.goto("/auth/signin?referer=%2Fwelcome");
  await expect(page.getByTestId("signin-container")).toBeVisible({
    timeout: 60_000,
  });
  const root = authDialog(page);
  await expect(root).toBeVisible({ timeout: 60_000 });
  await root
    .getByTestId("signin-email")
    .locator('input[name="email"]')
    .fill(email);
  await root
    .getByTestId("signin-password")
    .locator('input[name="password"]')
    .fill(password);
  await root.getByTestId("signin-submit").getByRole("button").click();
}

test.describe("pw-totp enroll account settings", () => {
  test("totp_enroll_happy", async ({ page, auth }) => {
    const email = `totp-enroll-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);
    await enrollTotpToEnabled(page);
  });

  test("totp_enroll_bad_code_sad", async ({ page, auth }) => {
    const email = `totp-bad-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);

    await expect(page.getByTestId("totp-settings-idle")).toBeVisible();
    await startTotpSetup(page);
    const secret = await totpSecretFromManualLocator(
      page.getByTestId("totp-settings-manual-secret"),
    );
    await clickTestId(page, "totp-settings-continue");
    await page.getByTestId("totp-settings-code").fill("000000");
    await clickTestId(page, "totp-settings-confirm-submit");

    await expect(page.getByTestId("totp-settings-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("totp-settings-error")).toContainText(
      /incorrect code/i,
    );
    await expect(page.getByTestId("totp-settings-confirm")).toBeVisible();

    await page.getByTestId("totp-settings-code").fill(await totpCode(secret));
    await clickTestId(page, "totp-settings-confirm-submit");
    await expect(page.getByTestId("totp-settings-recovery")).toBeVisible({
      timeout: 30_000,
    });
  });

  test("totp_disable_happy", async ({ page, auth }) => {
    const email = `totp-disable-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);
    const { secret } = await enrollTotpToEnabled(page);

    await clickTestId(page, "totp-settings-disable-start");
    await expect(page.getByTestId("totp-settings-disable")).toBeVisible();
    await page
      .getByTestId("totp-settings-disable-code")
      .fill(await totpCode(secret));
    await clickTestId(page, "totp-settings-disable-submit");
    await expect(page.getByTestId("totp-settings-idle")).toBeVisible({
      timeout: 30_000,
    });
  });

  test("totp_regenerate_happy", async ({ page, auth }) => {
    const email = `totp-regen-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);
    const { secret, recoveryCodes: oldCodes } = await enrollTotpToEnabled(page);

    await clickTestId(page, "totp-settings-regen-start");
    await expect(page.getByTestId("totp-settings-regen")).toBeVisible();
    await page.getByTestId("totp-settings-regen-code").fill(await totpCode(secret));
    await clickTestId(page, "totp-settings-regen-submit");

    await expect(page.getByTestId("totp-settings-recovery")).toBeVisible({
      timeout: 30_000,
    });
    const newText = await page
      .getByTestId("totp-settings-recovery-list")
      .innerText();
    const newCodes = parseRecoveryCodes(newText);
    expect(newCodes.length).toBe(8);
    expect(newCodes).not.toEqual(oldCodes);

    await page
      .getByTestId("totp-settings-recovery-ack")
      .locator('input[type="checkbox"]')
      .check();
    await clickTestId(page, "totp-settings-recovery-done");
    await expect(page.getByTestId("totp-settings-enabled")).toBeVisible({
      timeout: 30_000,
    });

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    const root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(newCodes[0]!);
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });
});
