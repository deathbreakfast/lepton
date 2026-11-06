import {
  test,
  expect,
  seedTestData,
  clearMailpit,
  clearSmsSink,
  waitMailpitCode,
  waitSmsOtp,
  signInAs,
  signupNewUser,
  clickTestId,
} from "./fixtures";

/**
 * Click Continue on the account-settings prompt until the confirm page opens.
 * A click made before the page hydrates is dropped, so retry while the prompt
 * is still showing.
 */
async function continueFromPrompt(page: import("@playwright/test").Page) {
  await expect(async () => {
    if (!/\/user\/confirm-account/.test(page.url())) {
      await clickTestId(page, "confirm-account-prompt-continue");
    }
    await expect(page).toHaveURL(/\/user\/confirm-account/, {
      timeout: 10_000,
    });
  }).toPass({ timeout: 60_000 });
}

async function expectEmailStep(page: import("@playwright/test").Page) {
  await expect(page.getByTestId("confirm-account-container")).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.getByTestId("confirm-step-email")).toBeVisible();
}

async function expectPhoneStep(page: import("@playwright/test").Page) {
  await expect(page.getByTestId("confirm-step-phone")).toBeVisible({
    timeout: 60_000,
  });
}

async function expectConfirmStep(page: import("@playwright/test").Page) {
  await expect(page.getByTestId("confirm-step-confirm")).toBeVisible({
    timeout: 60_000,
  });
}

test.describe("pw-confirm funnel + re-entry", () => {
  test.beforeEach(async ({ request }) => {
    await clearMailpit(request);
    await clearSmsSink(request);
  });

  test("pw-confirm-signup-lands-happy", async ({ page }) => {
    const email = `confirm-signup-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expect(page).toHaveURL(/\/user\/confirm-account/, { timeout: 60_000 });
    await expectEmailStep(page);
    await expect(page.getByTestId("confirm-step-indicator")).toContainText(
      "Email ●",
    );
  });

  test("pw-confirm-route-requires-auth-sad", async ({ page }) => {
    await page.goto("/user/confirm-account");
    await expect(page.getByTestId("confirm-account-container")).toBeVisible({
      timeout: 60_000,
    });
    // Unauthenticated status fails closed — no email step controls for a session.
    await expect(page.getByTestId("confirm-step-email")).toHaveCount(0);
    await expect(page.getByTestId("confirm-email-verify")).toHaveCount(0);
  });

  test("pw-confirm-signin-unverified-lands-happy", async ({ page, request }) => {
    const email = `confirm-unverified-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_unverified_user", { email, password });
    await signInAs(page, email, password, "/welcome");
    await expect(page).toHaveURL(/\/user\/confirm-account/, { timeout: 60_000 });
    await expectEmailStep(page);
  });

  test("pw-confirm-signin-unconfirmed-allows-app-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-unconf-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
    await expect(page.getByTestId("confirm-incomplete-banner")).toBeVisible();
  });

  test("pw-confirm-email-verify-happy", async ({ page, request }) => {
    const email = `confirm-email-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expectEmailStep(page);
    const code = await waitMailpitCode(request, email);
    await page.getByTestId("confirm-email-token").locator("input").fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expectPhoneStep(page);
  });

  test("pw-confirm-email-bad-token-sad", async ({ page }) => {
    const email = `confirm-badtok-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expectEmailStep(page);
    await page
      .getByTestId("confirm-email-token")
      .locator("input")
      .fill("not-a-real-token");
    await clickTestId(page, "confirm-email-verify");
    await expect(page.getByTestId("confirm-email-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("confirm-step-phone")).toHaveCount(0);
  });

  test("pw-confirm-email-resend-inside-cooldown-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-resend-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expectEmailStep(page);
    const code = await waitMailpitCode(request, email);
    await clearMailpit(request);
    // Signup just sent a code, so the resend is a no-op that still reports success
    // and leaves the first code valid.
    await clickTestId(page, "confirm-email-resend");
    await expect(page.getByTestId("confirm-email-success")).toBeVisible({
      timeout: 30_000,
    });
    await page.getByTestId("confirm-email-token").locator("input").fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expectPhoneStep(page);
  });

  test("pw-confirm-email-lockout-sad", async ({ page, request }) => {
    const email = `confirm-lockout-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expectEmailStep(page);
    const code = await waitMailpitCode(request, email);
    const wrong = code === "000000" ? "111111" : "000000";
    const input = page.getByTestId("confirm-email-token").locator("input");
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await input.fill(wrong);
      await clickTestId(page, "confirm-email-verify");
      await expect(page.getByTestId("confirm-email-error")).toBeVisible({
        timeout: 30_000,
      });
    }
    await expect(page.getByTestId("confirm-email-error")).toContainText(
      "Too many attempts",
    );
    // Locked: the right code is refused too.
    await input.fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expect(page.getByTestId("confirm-email-error")).toContainText(
      "Too many attempts",
    );
    await expect(page.getByTestId("confirm-step-phone")).toHaveCount(0);
  });

  test("pw-confirm-email-step-locked-after-verified-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-emailonly-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectPhoneStep(page);
  });

  test("pw-confirm-phone-send-verify-happy", async ({ page, request }) => {
    const email = `confirm-phone-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("+15555550111");
    await clickTestId(page, "confirm-phone-send");
    const otp = await waitSmsOtp(request);
    await page.getByTestId("confirm-phone-otp").locator("input").fill(otp);
    await clickTestId(page, "confirm-phone-verify");
    await expectConfirmStep(page);
  });

  test("pw-confirm-phone-national-format-happy", async ({ page, request }) => {
    const email = `confirm-phone-nat-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("(555) 555-0113");
    await clickTestId(page, "confirm-phone-send");
    const otp = await waitSmsOtp(request);
    await page.getByTestId("confirm-phone-otp").locator("input").fill(otp);
    await clickTestId(page, "confirm-phone-verify");
    await expectConfirmStep(page);
  });

  test("pw-confirm-phone-invalid-e164-sad", async ({ page, request }) => {
    const email = `confirm-bade164-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("not-a-phone");
    await clickTestId(page, "confirm-phone-send");
    await expect(page.getByTestId("confirm-phone-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("confirm-phone-error")).toContainText(
      /invalid_phone|valid phone/i,
    );
    await expect(page.getByTestId("confirm-step-confirm")).toHaveCount(0);
  });

  test("pw-confirm-phone-bad-otp-sad", async ({ page, request }) => {
    const email = `confirm-badotp-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("+15555550112");
    await clickTestId(page, "confirm-phone-send");
    await waitSmsOtp(request);
    await page.getByTestId("confirm-phone-otp").locator("input").fill("000000");
    await clickTestId(page, "confirm-phone-verify");
    await expect(page.getByTestId("confirm-phone-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("confirm-step-confirm")).toHaveCount(0);
  });

  test("pw-confirm-phone-step-locked-without-email-sad", async ({
    page,
    request,
  }) => {
    const email = `confirm-phonelock-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_unverified_user", { email, password });
    await signInAs(page, email, password, "/welcome");
    await expectEmailStep(page);
    await expect(page.getByTestId("confirm-step-phone")).toHaveCount(0);
    await expect(page.getByTestId("confirm-phone-send")).toHaveCount(0);
  });

  test("pw-confirm-cta-blocked-before-phone-sad", async ({ page, request }) => {
    const email = `confirm-ctablock-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectPhoneStep(page);
    await expect(page.getByTestId("confirm-account-submit")).toHaveCount(0);
  });

  test("pw-confirm-cta-happy", async ({ page, request }) => {
    const email = `confirm-cta-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_ready", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/confirm-account");
    await expectConfirmStep(page);
    await clickTestId(page, "confirm-account-submit");
    await expect(page.getByTestId("confirm-account-success")).toBeVisible({
      timeout: 30_000,
    });
    await page.goto("/welcome");
    await expect(page.getByTestId("confirm-incomplete-banner")).toHaveCount(0);
    await page.goto("/user/account-settings");
    await expect(
      page.getByTestId("confirm-account-prompt-continue"),
    ).toHaveCount(0);
  });

  test("pw-confirm-full-funnel-happy", async ({ page, request }) => {
    const email = `confirm-full-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expectEmailStep(page);
    const code = await waitMailpitCode(request, email);
    await page.getByTestId("confirm-email-token").locator("input").fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("+15555550116");
    await clickTestId(page, "confirm-phone-send");
    const otp = await waitSmsOtp(request);
    await page.getByTestId("confirm-phone-otp").locator("input").fill(otp);
    await clickTestId(page, "confirm-phone-verify");
    await expectConfirmStep(page);
    await clickTestId(page, "confirm-account-submit");
    await expect(page.getByTestId("confirm-account-success")).toBeVisible({
      timeout: 30_000,
    });
  });

  test("pw-confirm-skip-keeps-app-usable-happy", async ({ page }) => {
    const email = `confirm-skip-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await expectEmailStep(page);
    await clickTestId(page, "confirm-skip");
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
    await expect(page.getByTestId("confirm-incomplete-banner")).toBeVisible();
    await page.goto("/user/account-settings");
    await expect(page.getByTestId("confirm-account-prompt")).toBeVisible();
    await expect(
      page.getByTestId("confirm-account-prompt-continue"),
    ).toBeVisible();
  });

  test("pw-confirm-skip-from-phone-reentry-happy", async ({ page, request }) => {
    const email = `confirm-skipphone-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    const code = await waitMailpitCode(request, email);
    await page.getByTestId("confirm-email-token").locator("input").fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expectPhoneStep(page);
    await clickTestId(page, "confirm-skip");
    await page.goto("/user/account-settings");
    await continueFromPrompt(page);
    await expect(page).toHaveURL(/\/user\/confirm-account/, { timeout: 60_000 });
    await expectPhoneStep(page);
  });

  test("pw-confirm-banner-continue-happy", async ({ page, request }) => {
    const email = `confirm-banner-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await expect(page.getByTestId("confirm-incomplete-banner")).toBeVisible({
      timeout: 60_000,
    });
    await clickTestId(page, "confirm-incomplete-continue");
    await expect(page).toHaveURL(
      /\/user\/confirm-account\?referer=%2Fwelcome/,
      { timeout: 60_000 },
    );
    await expectPhoneStep(page);
  });

  test("pw-confirm-banner-hidden-when-confirmed-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-donebanner-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_done", { email, password });
    await signInAs(page, email, password, "/welcome");
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("confirm-incomplete-banner")).toHaveCount(0);
  });

  test("pw-confirm-prompt-settings-visible-happy", async ({ page, request }) => {
    const email = `confirm-promptvis-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/account-settings");
    await expect(page.getByTestId("confirm-account-prompt")).toBeVisible();
    await expect(page.getByTestId("confirm-account-prompt")).toContainText(
      "Not confirmed",
    );
    await expect(
      page.getByTestId("confirm-account-prompt-continue"),
    ).toBeVisible();
  });

  test("pw-confirm-prompt-settings-reentry-happy", async ({ page, request }) => {
    const email = `confirm-promptre-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/account-settings");
    await continueFromPrompt(page);
    await expect(page).toHaveURL(/\/user\/confirm-account/, { timeout: 60_000 });
  });

  test("pw-confirm-prompt-resume-email-happy", async ({ page, request }) => {
    const email = `confirm-resumee-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_unverified_user", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/account-settings");
    await continueFromPrompt(page);
    await expectEmailStep(page);
  });

  test("pw-confirm-prompt-resume-phone-happy", async ({ page, request }) => {
    const email = `confirm-resumep-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_email_only", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/account-settings");
    await continueFromPrompt(page);
    await expectPhoneStep(page);
  });

  test("pw-confirm-prompt-resume-confirm-happy", async ({ page, request }) => {
    const email = `confirm-resumec-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_ready", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/account-settings");
    await continueFromPrompt(page);
    await expectConfirmStep(page);
    await expect(page.getByTestId("confirm-account-submit")).toBeVisible();
  });

  test("pw-confirm-prompt-hidden-when-confirmed-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-promptdone-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await seedTestData(request, "auth_confirm_done", { email, password });
    await signInAs(page, email, password, "/welcome");
    await page.goto("/user/account-settings");
    await expect(
      page.getByTestId("confirm-account-prompt-confirmed"),
    ).toBeVisible({ timeout: 60_000 });
    await expect(
      page.getByTestId("confirm-account-prompt-continue"),
    ).toHaveCount(0);
  });

  test("pw-confirm-prompt-requires-auth-sad", async ({ page }) => {
    await page.goto("/user/account-settings");
    await expect(
      page.getByTestId("confirm-account-prompt-continue"),
    ).toHaveCount(0);
  });

  test("pw-confirm-reentry-finish-via-prompt-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-refinishp-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await clickTestId(page, "confirm-skip");
    await page.goto("/user/account-settings");
    await continueFromPrompt(page);
    await expectEmailStep(page);
    const code = await waitMailpitCode(request, email);
    await page.getByTestId("confirm-email-token").locator("input").fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("+15555550114");
    await clickTestId(page, "confirm-phone-send");
    const otp = await waitSmsOtp(request);
    await page.getByTestId("confirm-phone-otp").locator("input").fill(otp);
    await clickTestId(page, "confirm-phone-verify");
    await expectConfirmStep(page);
    await clickTestId(page, "confirm-account-submit");
    await expect(page.getByTestId("confirm-account-success")).toBeVisible({
      timeout: 30_000,
    });
    await page.goto("/welcome");
    await expect(page.getByTestId("confirm-incomplete-banner")).toHaveCount(0);
    await page.goto("/user/account-settings");
    await expect(
      page.getByTestId("confirm-account-prompt-continue"),
    ).toHaveCount(0);
  });

  test("pw-confirm-reentry-finish-via-banner-happy", async ({
    page,
    request,
  }) => {
    const email = `confirm-refinishb-${Date.now()}@example.com`;
    await signupNewUser(page, email);
    await clickTestId(page, "confirm-skip");
    await expect(page.getByTestId("confirm-incomplete-banner")).toBeVisible({
      timeout: 60_000,
    });
    await clickTestId(page, "confirm-incomplete-continue");
    await expectEmailStep(page);
    const code = await waitMailpitCode(request, email);
    await page.getByTestId("confirm-email-token").locator("input").fill(code);
    await clickTestId(page, "confirm-email-verify");
    await expectPhoneStep(page);
    await page
      .getByTestId("confirm-phone-e164")
      .locator("input")
      .fill("+15555550115");
    await clickTestId(page, "confirm-phone-send");
    const otp = await waitSmsOtp(request);
    await page.getByTestId("confirm-phone-otp").locator("input").fill(otp);
    await clickTestId(page, "confirm-phone-verify");
    await expectConfirmStep(page);
    await clickTestId(page, "confirm-account-submit");
    await expect(page.getByTestId("confirm-account-success")).toBeVisible({
      timeout: 30_000,
    });
    await page.goto("/welcome");
    await expect(page.getByTestId("confirm-incomplete-banner")).toHaveCount(0);
  });
});
