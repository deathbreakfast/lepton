import {
  test,
  expect,
  seedTestData,
  authDialog,
  resetDialog,
  clickTestId,
  submitSignin,
} from "./fixtures";

test.describe("pw-auth route pages", () => {
  test("pw-auth-nav-signin-signup", async ({ page }) => {
    await page.goto("/auth/signup");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    await expect(authDialog(page)).toBeVisible();
    await page.getByRole("link", { name: /sign in/i }).click();
    await expect(page).toHaveURL(/\/auth\/signin/);
    await expect(page.getByTestId("signin-container")).toBeVisible();
    await page.getByRole("link", { name: /create an account/i }).click();
    await expect(page).toHaveURL(/\/auth\/signup/);
  });

  test("pw-auth-signup-happy", async ({ page }) => {
    await page.goto("/auth/signup");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await expect(root).toBeVisible({ timeout: 60_000 });
    const email = `e2e-signup-${Date.now()}@example.com`;
    await root
      .getByTestId("signup-email")
      .locator('input[name="email"]')
      .fill(email);
    await root.getByTestId("signup-email-continue").getByRole("button").click();
    await expect(root.getByTestId("signup-page-details")).toBeVisible();
    await root
      .getByTestId("signup-legal-name")
      .locator('input[name="legal_name"]')
      .fill("Alex Rivera");
    await root
      .getByTestId("signup-display-name")
      .locator('input[name="display_name"]')
      .fill("Alex");
    await root
      .getByTestId("signup-password")
      .locator('input[name="password"]')
      .fill("CorrectHorseBattery1!");
    await root
      .getByTestId("signup-confirm")
      .locator('input[name="confirm"]')
      .fill("CorrectHorseBattery1!");
    await root.getByTestId("signup-submit").getByRole("button").click();
    await expect(root.getByTestId("signup-page-email-verify")).toBeVisible({
      timeout: 60_000,
    });
    await root.getByTestId("signup-email-skip").getByRole("button").click();
    await root.getByTestId("signup-phone-skip").getByRole("button").click();
    await root.getByTestId("signup-totp-skip").getByRole("button").click();
    await page.goto("/user/confirm-account");
    await expect(page.getByTestId("confirm-account-container")).toBeVisible({
      timeout: 60_000,
    });
  });

  test("pw-auth-signup-policy-sad", async ({ page }) => {
    await page.goto("/auth/signup");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await expect(root).toBeVisible({ timeout: 60_000 });
    await root
      .getByTestId("signup-email")
      .locator('input[name="email"]')
      .fill(`weak-${Date.now()}@example.com`);
    await root.getByTestId("signup-email-continue").getByRole("button").click();
    await expect(root.getByTestId("signup-page-details")).toBeVisible();
    await root
      .getByTestId("signup-legal-name")
      .locator('input[name="legal_name"]')
      .fill("Weak Pass");
    await root
      .getByTestId("signup-display-name")
      .locator('input[name="display_name"]')
      .fill("Weak");
    await root
      .getByTestId("signup-password")
      .locator('input[name="password"]')
      .fill("short");
    await root
      .getByTestId("signup-confirm")
      .locator('input[name="confirm"]')
      .fill("short");
    await root.getByTestId("signup-submit").getByRole("button").click();
    await expect(root.getByTestId("signup-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page).toHaveURL(/\/auth\/signup/);
  });

  test("pw-auth-signup-display-sad", async ({ page }) => {
    await page.goto("/auth/signup");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await expect(root).toBeVisible({ timeout: 60_000 });
    await root
      .getByTestId("signup-email")
      .locator('input[name="email"]')
      .fill(`bad-display-${Date.now()}@example.com`);
    await root.getByTestId("signup-email-continue").getByRole("button").click();
    await expect(root.getByTestId("signup-page-details")).toBeVisible();
    await root
      .getByTestId("signup-legal-name")
      .locator('input[name="legal_name"]')
      .fill("Alex Rivera");
    await root
      .getByTestId("signup-display-name")
      .locator('input[name="display_name"]')
      .fill("Name<script>");
    await root
      .getByTestId("signup-password")
      .locator('input[name="password"]')
      .fill("CorrectHorseBattery1!");
    await root
      .getByTestId("signup-confirm")
      .locator('input[name="confirm"]')
      .fill("CorrectHorseBattery1!");
    await root.getByTestId("signup-submit").getByRole("button").click();
    await expect(root.getByTestId("signup-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page).toHaveURL(/\/auth\/signup/);
  });

  test("pw-auth-signin-happy", async ({ page, auth }) => {
    const email = `signin-ok-${Date.now()}@example.com`;
    await auth.signIn({
      email,
      password: "CorrectHorseBattery1!",
      referer: "/welcome",
    });
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });

  test("pw-auth-signin-bad-creds-sad", async ({ page, request }) => {
    const email = `signin-bad-${Date.now()}@example.com`;
    await seedTestData(request, "auth_basic_user", {
      email,
      password: "CorrectHorseBattery1!",
    });
    await page.goto("/auth/signin");
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
      .fill("WrongPassword999!");
    await root.getByTestId("signin-submit").getByRole("button").click();
    await expect(root.getByTestId("signin-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("user-menu-signin")).toBeVisible();
  });

  test("pw-auth-logout-happy", async ({ page, auth }) => {
    const email = `logout-${Date.now()}@example.com`;
    await auth.signIn({
      email,
      password: "CorrectHorseBattery1!",
      referer: "/welcome",
    });
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
    await page.goto("/auth/logout");
    await expect(page.getByTestId("logout-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await root.getByTestId("logout-button").getByRole("button").click();
    await expect(page.getByTestId("user-menu-signin")).toBeVisible({
      timeout: 60_000,
    });
  });

  test("pw-auth-reset-request-happy", async ({ page }) => {
    await page.goto("/auth/reset/request");
    await expect(
      page.getByTestId("password-reset-request-container"),
    ).toBeVisible({ timeout: 60_000 });
    const dialog = resetDialog(page);
    await expect(dialog).toBeVisible({ timeout: 60_000 });
    await dialog
      .getByTestId("password-reset-request-email")
      .locator('input[name="email"]')
      .fill("anyone@example.com");
    await dialog
      .getByTestId("password-reset-request-submit")
      .getByRole("button")
      .click();
    await expect(
      dialog.getByTestId("password-reset-request-success"),
    ).toBeVisible({ timeout: 30_000 });
  });

  test("pw-auth-reset-confirm-happy", async ({ page, request }) => {
    const email = `reset-ok-${Date.now()}@example.com`;
    const seeded = await seedTestData(request, "auth_reset_token", {
      email,
      password: "CorrectHorseBattery1!",
    });
    expect(seeded.reset_token).toBeTruthy();
    await page.goto(
      `/auth/reset/confirm?token=${encodeURIComponent(seeded.reset_token!)}`,
    );
    await expect(
      page.getByTestId("password-reset-confirm-container"),
    ).toBeVisible({ timeout: 60_000 });
    const dialog = resetDialog(page);
    await expect(dialog).toBeVisible({ timeout: 60_000 });
    const newPass = "NewCorrectHorseBattery2!";
    await dialog.locator('input[name="new_password"]').fill(newPass);
    await dialog.locator('input[name="confirm_password"]').fill(newPass);
    await dialog.getByRole("button", { name: /reset password/i }).click();
    await expect(dialog.getByText(/password reset complete/i)).toBeVisible({
      timeout: 30_000,
    });
    await page.goto("/auth/signin?referer=/welcome");
    await expect(page.getByTestId("signin-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await root
      .getByTestId("signin-email")
      .locator('input[name="email"]')
      .fill(email);
    await root
      .getByTestId("signin-password")
      .locator('input[name="password"]')
      .fill(newPass);
    await root.getByTestId("signin-submit").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
  });

  test("pw-auth-reset-confirm-bad-token-sad", async ({ page }) => {
    await page.goto("/auth/reset/confirm?token=not-a-real-token");
    await expect(
      page.getByTestId("password-reset-confirm-container"),
    ).toBeVisible({ timeout: 60_000 });
    const dialog = resetDialog(page);
    await dialog
      .locator('input[name="new_password"]')
      .fill("CorrectHorseBattery1!");
    await dialog
      .locator('input[name="confirm_password"]')
      .fill("CorrectHorseBattery1!");
    await dialog.getByRole("button", { name: /reset password/i }).click();
    await expect(
      dialog.getByTestId("password-reset-confirm-error"),
    ).toBeVisible({ timeout: 30_000 });
  });
});

test.describe("pw-auth dialog", () => {
  test("pw-auth-dialog-signin-happy", async ({ page, request }) => {
    const email = `dialog-ok-${Date.now()}@example.com`;
    await seedTestData(request, "auth_basic_user", {
      email,
      password: "CorrectHorseBattery1!",
    });
    await page.goto("/");
    await expect(page.getByTestId("user-menu-signin")).toBeVisible({
      timeout: 60_000,
    });
    await clickTestId(page, "user-menu-signin");
    const root = authDialog(page);
    await expect(root).toBeVisible();
    await submitSignin(page, email, "CorrectHorseBattery1!");
    await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
  });

  test("pw-auth-dialog-signin-sad", async ({ page, request }) => {
    const email = `dialog-bad-${Date.now()}@example.com`;
    await seedTestData(request, "auth_basic_user", {
      email,
      password: "CorrectHorseBattery1!",
    });
    await page.goto("/");
    await clickTestId(page, "user-menu-signin");
    const root = authDialog(page);
    await expect(root).toBeVisible({ timeout: 60_000 });
    await root
      .getByTestId("signin-email")
      .locator('input[name="email"]')
      .fill(email);
    await root
      .getByTestId("signin-password")
      .locator('input[name="password"]')
      .fill("nope-nope-nope");
    await root.getByTestId("signin-submit").getByRole("button").click();
    await expect(root.getByTestId("signin-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("user-menu-signin")).toBeVisible();
  });
});
