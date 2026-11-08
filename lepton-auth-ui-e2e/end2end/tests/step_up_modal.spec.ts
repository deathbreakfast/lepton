import {
  test,
  expect,
  seedTestData,
  authDialog,
  clickTestId,
} from "./fixtures";
import { totpCode } from "./helpers/totp";

function stepUpDialog(page: import("@playwright/test").Page) {
  return page.getByTestId("step-up-dialog");
}

async function signInWithPassword(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
  totpSecret?: string,
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

  if (totpSecret) {
    await expect(root.getByTestId("signin-mfa-step")).toBeVisible({
      timeout: 30_000,
    });
    await root
      .getByTestId("signin-mfa-totp")
      .locator('input[name="code"]')
      .fill(await totpCode(totpSecret));
    await root.getByTestId("signin-mfa-submit").getByRole("button").click();
  }

  await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
}

async function gotoStepUpDemo(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
  totpSecret?: string,
) {
  await signInWithPassword(page, email, password, totpSecret);
  await page.goto("/user/step-up-demo");
  await expect(page.getByTestId("step-up-demo-container")).toBeVisible({
    timeout: 60_000,
  });
}

test.describe("pw-step-up-modal", () => {
  test("step_up_modal_totp_happy", async ({ page, request }) => {
    const email = `step-up-ok-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root
      .getByTestId("step-up-totp")
      .locator("input")
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("step-up-submit").getByRole("button").click();

    await expect(root).toBeHidden({ timeout: 30_000 });
    await expect(page.getByTestId("step-up-demo-success")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("step-up-demo-result")).toHaveText("success");
  });

  test("step_up_modal_totp_sad_wrong_code", async ({ page, request }) => {
    const email = `step-up-bad-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root.getByTestId("step-up-totp").locator("input").fill("000000");
    await root.getByTestId("step-up-submit").getByRole("button").click();

    await expect(root.getByTestId("step-up-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("step-up-error")).toContainText(
      /Authenticator code is incorrect/i,
    );
    await expect(root).toBeVisible();
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
  });

  test("step_up_modal_totp_sad_empty", async ({ page, request }) => {
    const email = `step-up-empty-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root.getByTestId("step-up-submit").getByRole("button").click();

    await expect(root.getByTestId("step-up-error")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
    await expect(page.getByTestId("step-up-demo-result")).toHaveText("idle");
  });

  test("step_up_modal_cancel", async ({ page, request }) => {
    const email = `step-up-cancel-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root.getByTestId("step-up-cancel").getByRole("button").click();

    await expect(root).toBeHidden({ timeout: 15_000 });
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
    await expect(page).toHaveURL(/\/user\/step-up-demo/);
  });

  test("step_up_modal_backdrop_no_dismiss", async ({ page, request }) => {
    const email = `step-up-backdrop-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });

    await page.keyboard.press("Escape");
    await expect(root).toBeVisible();

    const backdrop = page.locator(".orbital-backdrop").filter({ visible: true });
    if ((await backdrop.count()) > 0) {
      await backdrop.first().click({ position: { x: 4, y: 4 }, force: true });
    }
    await expect(root).toBeVisible();
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
  });

  test("step_up_modal_no_totp_enrolled", async ({ page, auth }) => {
    const email = `step-up-no-totp-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";

    await auth.signIn({ email, password, referer: "/welcome" });
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await page.goto("/user/step-up-demo");
    await expect(page.getByTestId("step-up-demo-container")).toBeVisible({
      timeout: 60_000,
    });
    await clickTestId(page, "step-up-demo-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await expect(root.getByTestId("step-up-not-enrolled")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("step-up-totp")).toHaveCount(0);
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
  });

  test("step_up_modal_password_and_totp_happy", async ({ page, request }) => {
    const email = `step-up-pw-ok-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-password-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root
      .getByTestId("step-up-password")
      .locator("input")
      .fill(password);
    await root
      .getByTestId("step-up-totp")
      .locator("input")
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("step-up-submit").getByRole("button").click();

    await expect(page.getByTestId("step-up-demo-success")).toBeVisible({
      timeout: 30_000,
    });
  });

  test("step_up_modal_password_and_totp_sad_bad_password", async ({
    page,
    request,
  }) => {
    const email = `step-up-pw-bad-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-password-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root
      .getByTestId("step-up-password")
      .locator("input")
      .fill("WrongPassword!!!!1");
    await root
      .getByTestId("step-up-totp")
      .locator("input")
      .fill(await totpCode(seeded.totp_secret!));
    await root.getByTestId("step-up-submit").getByRole("button").click();

    await expect(root.getByTestId("step-up-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("step-up-error")).toContainText(
      /Current password is incorrect/i,
    );
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
  });

  test("step_up_modal_password_and_totp_sad_bad_totp", async ({
    page,
    request,
  }) => {
    const email = `step-up-pw-badtotp-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    const seeded = await seedTestData(request, "auth_user_with_totp", {
      email,
      password,
    });
    expect(seeded.totp_secret).toBeTruthy();

    await gotoStepUpDemo(page, email, password, seeded.totp_secret!);
    await clickTestId(page, "step-up-demo-password-totp-trigger");

    const root = stepUpDialog(page);
    await expect(root).toBeVisible({ timeout: 30_000 });
    await root
      .getByTestId("step-up-password")
      .locator("input")
      .fill(password);
    await root.getByTestId("step-up-totp").locator("input").fill("000000");
    await root.getByTestId("step-up-submit").getByRole("button").click();

    await expect(root.getByTestId("step-up-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(root.getByTestId("step-up-error")).toContainText(
      /Authenticator code is incorrect/i,
    );
    await expect(page.getByTestId("step-up-demo-success")).toHaveCount(0);
  });
});
