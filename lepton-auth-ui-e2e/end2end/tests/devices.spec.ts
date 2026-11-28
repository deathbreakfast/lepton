import {
  test,
  expect,
  installVirtualAuthenticator,
  clickTestId,
  waitForHydration,
} from "./fixtures";

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
  await expect(page.getByTestId("devices-section")).toBeVisible();
  await waitForHydration(page);
}

test.describe("pw-devices account settings", () => {
  test("devices_list_requires_auth_sad", async ({ page }) => {
    await page.goto("/user/account-settings");
    await expect(page.getByTestId("account-settings-container")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("devices-section")).toBeVisible();
    await expect(page.getByTestId("devices-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("devices-error")).toContainText(/signed in/i);
  });

  test("devices_trusted_browser_happy", async ({ page, auth }) => {
    const email = `devices-tb-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);

    await page.getByTestId("devices-browser-label").locator("input").fill("E2E laptop");
    await clickTestId(page, "devices-remember-browser");
    await expect(page.getByTestId("devices-confirm-code")).toBeVisible({
      timeout: 30_000,
    });
    const code = await page
      .getByTestId("devices-confirm-code")
      .locator("input")
      .inputValue();
    expect(code.length).toBeGreaterThan(0);
    await clickTestId(page, "devices-confirm-browser");
    await expect(page.getByTestId("devices-list")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("devices-row")).toContainText(/E2E laptop/i);
    await expect(page.getByTestId("devices-row")).toContainText(/Trusted/i);
  });

  test("devices_passkey_enroll_happy", async ({ page, context, auth }) => {
    await page.goto("/");
    await installVirtualAuthenticator(context, page);

    const email = `devices-pk-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);
    await expect(page.getByTestId("devices-add-passkey")).toBeVisible({
      timeout: 60_000,
    });

    const labelInput = page.getByTestId("devices-passkey-label").locator("input");
    await labelInput.fill("E2E passkey");
    await expect(labelInput).toHaveValue("E2E passkey");
    await clickTestId(page, "devices-add-passkey");
    await expect(page.getByTestId("devices-list")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("devices-row")).toContainText(/E2E passkey/i);
    await expect(page.getByTestId("devices-row")).toContainText(/Passkey/i);
  });

  test("devices_passkey_enroll_rejected_sad", async ({ page, auth }) => {
    const email = `devices-pk-sad-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);
    await expect(page.getByTestId("devices-add-passkey")).toBeVisible();

    // Force authenticator cancel (no hanging native prompt).
    await page.evaluate(() => {
      const creds = navigator.credentials;
      creds.create = () =>
        Promise.reject(
          new DOMException(
            "The operation either timed out or was not allowed.",
            "NotAllowedError",
          ),
        );
    });

    await page.getByTestId("devices-passkey-label").locator("input").fill("Should fail");
    await clickTestId(page, "devices-add-passkey");
    await expect(page.getByTestId("devices-error")).toBeVisible({
      timeout: 30_000,
    });
  });

  test("devices_revoke_happy", async ({ page, auth }) => {
    const email = `devices-revoke-${Date.now()}@example.com`;
    const password = "CorrectHorseBattery1!";
    await gotoAccountSettingsSignedIn(page, auth, email, password);

    await page.getByTestId("devices-browser-label").locator("input").fill("Revoke me");
    await clickTestId(page, "devices-remember-browser");
    await expect(page.getByTestId("devices-confirm-code")).toBeVisible({
      timeout: 30_000,
    });
    await clickTestId(page, "devices-confirm-browser");
    await expect(page.getByTestId("devices-row")).toContainText(/Revoke me/i, {
      timeout: 30_000,
    });
    await expect(page.getByTestId("devices-row")).toContainText(/Trusted/i);

    await clickTestId(page, "devices-revoke");
    await expect(page.getByTestId("devices-empty")).toBeVisible({
      timeout: 30_000,
    });
  });
});
