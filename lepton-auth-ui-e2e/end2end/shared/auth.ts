import { expect } from "@playwright/test";
import { seedTestData } from "./seed";

/** Best-effort: clear portaled auth chrome that intercepts funnel clicks. */
export async function dismissAuthOverlay(
  page: import("@playwright/test").Page,
): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await page.keyboard.press("Escape").catch(() => undefined);
  }
  const visibleBackdrop = page
    .locator(".orbital-backdrop")
    .filter({ visible: true });
  try {
    await expect(visibleBackdrop).toHaveCount(0, { timeout: 5_000 });
  } catch {
    // Leave page usable; callers may force-click funnel controls.
  }
}

/** Click an Orbital Button wrapped in a native `data-testid` element. */
export async function clickTestId(
  page: import("@playwright/test").Page,
  testId: string,
): Promise<void> {
  const target = page.getByTestId(testId).getByRole("button");
  await expect(target).toBeVisible({ timeout: 30_000 });
  await expect(target).toBeEnabled({ timeout: 30_000 });
  try {
    await target.click({ timeout: 5_000 });
  } catch {
    await target.click({ force: true, timeout: 15_000 });
  }
}

/** Auth modal body (portaled); prefer over page-shell containers for form fills. */
export function authDialog(page: import("@playwright/test").Page) {
  return page.getByTestId("auth-dialog-root");
}

/** Password-reset modal (portaled). */
export function resetDialog(page: import("@playwright/test").Page) {
  return page.getByRole("dialog");
}

export async function signInAs(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
  referer = "/welcome",
): Promise<void> {
  const qs =
    referer && referer !== "/"
      ? `?referer=${encodeURIComponent(referer)}`
      : "";
  await page.goto(`/auth/signin${qs}`);
  await expect(page.getByTestId("signin-container")).toBeVisible({
    timeout: 60_000,
  });
  const root = authDialog(page);
  await expect(root).toBeVisible({ timeout: 60_000 });
  await submitSignin(page, email, password);
  await expect(page).not.toHaveURL(/\/auth\/signin/, { timeout: 60_000 });
  await dismissAuthOverlay(page);
}

/**
 * Fill the sign-in form and submit it. A submit made before the page hydrates
 * is dropped (and can clear the fields), so refill and retry until the
 * password error or a navigation shows the submit was handled.
 */
export async function submitSignin(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
): Promise<void> {
  const root = authDialog(page);
  const start = page.url();
  await expect(async () => {
    if (page.url() !== start) return;
    await root
      .getByTestId("signin-email")
      .locator('input[name="email"]')
      .fill(email);
    await root
      .getByTestId("signin-password")
      .locator('input[name="password"]')
      .fill(password);
    await root.getByTestId("signin-submit").getByRole("button").click();
    await page.waitForURL((url) => url.href !== start, { timeout: 8_000 });
  }).toPass({ timeout: 60_000 });
}

export async function signupNewUser(
  page: import("@playwright/test").Page,
  email: string,
  password = "CorrectHorseBattery1!",
): Promise<void> {
  await page.goto("/auth/signup");
  await expect(page.getByTestId("signup-container")).toBeVisible({
    timeout: 60_000,
  });
  const root = authDialog(page);
  await expect(root).toBeVisible({ timeout: 60_000 });
  await expect(root.getByTestId("signup-page-email")).toBeVisible();
  await root
    .getByTestId("signup-email")
    .locator('input[name="email"]')
    .fill(email);
  await root.getByTestId("signup-email-continue").getByRole("button").click();
  await expect(root.getByTestId("signup-page-details")).toBeVisible({
    timeout: 30_000,
  });
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
    .fill(password);
  await root
    .getByTestId("signup-confirm")
    .locator('input[name="confirm"]')
    .fill(password);
  await root.getByTestId("signup-submit").getByRole("button").click();
  await expect(root.getByTestId("signup-page-email-verify")).toBeVisible({
    timeout: 60_000,
  });
  await root.getByTestId("signup-email-skip").getByRole("button").click();
  await expect(root.getByTestId("signup-page-phone")).toBeVisible({
    timeout: 30_000,
  });
  await root.getByTestId("signup-phone-skip").getByRole("button").click();
  await expect(root.getByTestId("signup-page-totp")).toBeVisible({
    timeout: 30_000,
  });
  await root.getByTestId("signup-totp-skip").getByRole("button").click();
  // Soft-confirm still incomplete — dedicated confirm route for remaining steps.
  await page.goto("/user/confirm-account");
  await expect(page.getByTestId("confirm-account-container")).toBeVisible({
    timeout: 60_000,
  });
  await dismissAuthOverlay(page);
}

/** Seed `auth_basic_user` then complete the sign-in form. */
export async function seedAndSignIn(
  page: import("@playwright/test").Page,
  request: import("@playwright/test").APIRequestContext,
  opts: { email: string; password: string; referer?: string },
): Promise<void> {
  const { email, password, referer = "/welcome" } = opts;
  await seedTestData(request, "auth_basic_user", { email, password });
  const qs =
    referer && referer !== "/"
      ? `?referer=${encodeURIComponent(referer)}`
      : "";
  await page.goto(`/auth/signin${qs}`);
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

/** Install a Chromium virtual authenticator for WebAuthn ceremonies. */
export async function installVirtualAuthenticator(
  context: import("@playwright/test").BrowserContext,
  page: import("@playwright/test").Page,
): Promise<string> {
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return authenticatorId as string;
}
