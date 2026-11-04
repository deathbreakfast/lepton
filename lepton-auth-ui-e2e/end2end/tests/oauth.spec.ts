import { test, expect, authDialog } from "./fixtures";

test.describe("pw-oauth", () => {
  test("pw-oauth-buttons-visible", async ({ page }) => {
    await page.goto("/auth/signup");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await expect(root.getByTestId("oauth-continue-google")).toBeVisible();
    await expect(root.getByTestId("oauth-continue-github")).toBeVisible();
    await expect(root.getByTestId("oauth-continue-microsoft")).toBeVisible();

    await page.goto("/auth/signin");
    await expect(page.getByTestId("signin-container")).toBeVisible({
      timeout: 60_000,
    });
    const signin = authDialog(page);
    await expect(signin.getByTestId("oauth-continue-google")).toBeVisible();
    await expect(signin.getByTestId("oauth-continue-github")).toBeVisible();
    await expect(signin.getByTestId("oauth-continue-microsoft")).toBeVisible();
  });

  test("pw-oauth-signup-happy", async ({ page }) => {
    await page.goto("/auth/signup?referer=/welcome");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    const root = authDialog(page);
    await root.getByTestId("oauth-continue-google").getByRole("button").click();
    await expect(page).toHaveURL(/\/welcome(?:\?|$)/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });

  test("pw-oauth-signin-login-happy", async ({ page }) => {
    // First visit provisions via mock IdP.
    await page.goto("/auth/signup?referer=/welcome");
    await expect(page.getByTestId("signup-container")).toBeVisible({
      timeout: 60_000,
    });
    await authDialog(page)
      .getByTestId("oauth-continue-google")
      .getByRole("button")
      .click();
    await expect(page).toHaveURL(/\/welcome(?:\?|$)/, { timeout: 60_000 });

    // Sign out, then sign in again with the same mock identity.
    await page.goto("/auth/logout");
    await expect(page.getByTestId("logout-container")).toBeVisible({
      timeout: 60_000,
    });
    await authDialog(page)
      .getByTestId("logout-button")
      .getByRole("button")
      .click();
    await expect(page.getByTestId("user-menu-signin")).toBeVisible({
      timeout: 60_000,
    });

    await page.goto("/auth/signin?referer=/welcome");
    await expect(page.getByTestId("signin-container")).toBeVisible({
      timeout: 60_000,
    });
    await authDialog(page)
      .getByTestId("oauth-continue-google")
      .getByRole("button")
      .click();
    await expect(page).toHaveURL(/\/welcome(?:\?|$)/, { timeout: 60_000 });
    await expect(page.getByTestId("welcome-authenticated")).toBeVisible();
  });

  test("pw-oauth-state-sad", async ({ page }) => {
    await page.goto(
      "/auth/oauth/callback?code=mock-code&state=not-a-real-state",
    );
    await expect(page.getByTestId("oauth-callback-container")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("oauth-callback-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("user-menu-signin")).toBeVisible();
  });

  test("pw-auth-modal-width", async ({ page }) => {
    await page.goto("/auth/signin");
    await expect(page.getByTestId("signin-container")).toBeVisible({
      timeout: 60_000,
    });
    const signinBox = await authDialog(page).boundingBox();
    expect(signinBox).toBeTruthy();

    await page.goto("/auth/logout");
    await expect(page.getByTestId("logout-container")).toBeVisible({
      timeout: 60_000,
    });
    const logoutBox = await authDialog(page).boundingBox();
    expect(logoutBox).toBeTruthy();
    // Subpixel / font metrics can land just over 8px on some hosts (WSLg, DPI).
    expect(Math.abs((signinBox!.width ?? 0) - (logoutBox!.width ?? 0))).toBeLessThan(
      16,
    );
  });
});
