import {
  test,
  expect,
  seedTestData,
  authDialog,
  installVirtualAuthenticator,
  clickTestId,
} from "./fixtures";
import { totpCode } from "./helpers/totp";
import { enrollTotpToEnabled } from "./helpers/totp_settings";

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

test.describe("pw-signin-mfa", () => {
  test("signin_mfa_totp_happy", async ({ page, request }) => {
    const email = `mfa-totp-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await fillPasswordSignIn(page, email, password);
    const root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page).toHaveURL(/\/auth\/signin/);

    const code = await totpCode(seeded.totp_secret!);
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(code);
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();

    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });

  test("signin_mfa_totp_invalid_sad", async ({ page, request }) => {
    const email = `mfa-bad-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_user_with_totp", { email, password });

    await fillPasswordSignIn(page, email, password);
    const root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill("000000");
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();

    await expect(root.getByTestId("signin-mfa-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("signin-mfa-error")).toContainText(
      /Invalid authentication code|invalid/i,
    );
    await expect(page.getByTestId("welcome-authenticated")).toHaveCount(0);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible();
  });

  test("signin_mfa_trusted_browser_skip_happy", async ({ page, context, request }) => {
    const email = `mfa-tb-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });

    await fillPasswordSignIn(page, email, password);
    const root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("signin-mfa-remember")).toContainText(
      "30 days",
    );
    await root.getByTestId("signin-mfa-remember").locator('input[name="remember"]').check();
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });

    const cookies = await context.cookies();
    const device = cookies.find((c) => c.name === "lepton_device");
    expect(device?.httpOnly).toBeTruthy();
    expect(device?.expires).toBeGreaterThan(Date.now() / 1000 + 20 * 24 * 3600);
    expect(device?.expires).toBeLessThan(Date.now() / 1000 + 40 * 24 * 3600);

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
    await expect(authDialog(page).getByTestId("signin-mfa-step")).toHaveCount(0);
  });

  test("signin_mfa_webauthn_skip_happy", async ({ page, context, request }) => {
    await page.goto("/");
    await installVirtualAuthenticator(context, page);

    const email = `mfa-wa-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });

    await fillPasswordSignIn(page, email, password);
    let root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });

    await page.goto("/user/account-settings");
    await expect(page.getByTestId("devices-section")).toBeVisible({
      timeout: 60_000,
    });
    await page.getByTestId("devices-passkey-label").locator("input").fill("E2E MFA passkey");
    await clickTestId(page, "devices-add-passkey");
    await expect(page.getByTestId("devices-row")).toContainText(/E2E MFA passkey/i, {
      timeout: 60_000,
    });

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root.getByTestId("signin-mfa-passkey").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });

  test("signin_mfa_webauthn_reject_sad", async ({ page, context, request }) => {
    await page.goto("/");
    await installVirtualAuthenticator(context, page);

    const email = `mfa-wa-sad-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });

    await fillPasswordSignIn(page, email, password);
    let root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });

    await page.goto("/user/account-settings");
    await expect(page.getByTestId("devices-add-passkey")).toBeVisible({
      timeout: 60_000,
    });
    await page.getByTestId("devices-passkey-label").locator("input").fill("Reject passkey");
    await clickTestId(page, "devices-add-passkey");
    await expect(page.getByTestId("devices-row")).toContainText(/Reject passkey/i, {
      timeout: 60_000,
    });

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await page.evaluate(() => {
      const creds = navigator.credentials;
      creds.get = () =>
        Promise.reject(
          new DOMException(
            "The operation either timed out or was not allowed.",
            "NotAllowedError",
          ),
        );
    });
    await root.getByTestId("signin-mfa-passkey").getByRole("button").click();
    await expect(root.getByTestId("signin-mfa-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("welcome-authenticated")).toHaveCount(0);
  });

  test("signin_mfa_recovery_happy", async ({ page, auth }) => {
    const email = `mfa-recovery-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await auth.signIn({ email, password, referer: "/welcome" });
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await page.goto("/user/account-settings");
    await expect(page.getByTestId("totp-settings-section")).toBeVisible({
      timeout: 60_000,
    });
    const { recoveryCodes } = await enrollTotpToEnabled(page);

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    const root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("signin-mfa-recovery-hint")).toBeVisible();
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(recoveryCodes[0]!);
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });

  test("signin_mfa_recovery_reuse_sad", async ({ page, auth }) => {
    const email = `mfa-recovery-reuse-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await auth.signIn({ email, password, referer: "/welcome" });
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await page.goto("/user/account-settings");
    await expect(page.getByTestId("totp-settings-section")).toBeVisible({
      timeout: 60_000,
    });
    const { recoveryCodes } = await enrollTotpToEnabled(page);
    const used = recoveryCodes[0]!;

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    let root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(used);
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(used);
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(root.getByTestId("signin-mfa-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("welcome-authenticated")).toHaveCount(0);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible();
  });

  test("signin_mfa_revoke_clears_skip_happy", async ({ page, context, request }) => {
    const email = `mfa-revoke-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });

    await fillPasswordSignIn(page, email, password);
    let root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root.getByTestId("signin-mfa-remember").locator('input[name="remember"]').check();
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    expect(
      (await context.cookies()).some((c) => c.name === "lepton_device"),
    ).toBeTruthy();

    await page.goto("/user/account-settings");
    await expect(page.getByTestId("devices-row")).toBeVisible({ timeout: 60_000 });
    await clickTestId(page, "devices-revoke");
    await expect(page.getByTestId("devices-row")).toHaveCount(0, {
      timeout: 30_000,
    });

    await logout(page);
    await fillPasswordSignIn(page, email, password);
    root = authDialog(page);
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
  });
});
