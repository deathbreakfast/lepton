import {
  test,
  expect,
  clearMailpit,
  clearSmsSink,
  clickTestId,
  signInAs,
  signupNewUser,
  waitMailpitCode,
  waitSmsOtp,
} from "./fixtures";

type Page = import("@playwright/test").Page;
type Request = import("@playwright/test").APIRequestContext;

async function seedDelivery(request: Request) {
  const tag = `${Date.now()}${Math.floor(Math.random() * 1000)}`;
  const admin = `delivery-admin-${tag}@example.com`;
  const plain = `delivery-plain-${tag}@example.com`;
  const res = await request.post("/api/test/seed-delivery", {
    data: { admin_email: admin, plain_email: plain },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  const body = (await res.json()) as { password: string };
  return { admin, plain, password: body.password };
}

async function fill(page: Page, testId: string, value: string) {
  const input = page.getByTestId(testId).locator("input");
  await input.fill(value);
}

async function openDelivery(page: Page, email: string, password: string) {
  await signInAs(page, email, password, "/welcome");
  await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
  await page.goto("/lab/delivery");
  await expect(page.getByTestId("delivery-settings-container")).toBeVisible({
    timeout: 60_000,
  });
}

async function saveEmail(
  page: Page,
  driver: string,
  extra: { host?: string; port?: string; from?: string; sendgrid?: string } = {},
) {
  await fill(page, "delivery-email-driver", driver);
  await fill(page, "delivery-email-host", extra.host ?? "127.0.0.1");
  await fill(page, "delivery-email-port", extra.port ?? process.env.UF_SMTP_PORT ?? "1025");
  await fill(page, "delivery-email-from", extra.from ?? "noreply@example.test");
  await fill(page, "delivery-email-sendgrid", extra.sendgrid ?? "");
  await clickTestId(page, "delivery-email-save");
}

async function saveSms(page: Page, mode: string, secret: string) {
  await fill(page, "delivery-sms-mode", mode);
  await fill(page, "delivery-sms-secret", secret);
  await clickTestId(page, "delivery-sms-save");
}

test.describe("pw-lepton-delivery-settings", () => {
  test.afterEach(async ({ request }) => {
    const res = await request.post("/api/test/delivery-reset");
    expect(res.ok()).toBeTruthy();
  });

  test("pw-lepton-delivery-settings-happy", async ({ page, request, browser }) => {
    const { admin, password } = await seedDelivery(request);
    await clearMailpit(request);
    await clearSmsSink(request);
    await openDelivery(page, admin, password);

    // Email off: sign-up sends nothing.
    await saveEmail(page, "off");
    await expect(page.getByTestId("delivery-summary")).toContainText("email=noop");
    const baseURL = test.info().project.use.baseURL;
    const ctx = await browser.newContext({ baseURL });
    const guest = await ctx.newPage();
    const quiet = `delivery-quiet-${Date.now()}@example.com`;
    await signupNewUser(guest, quiet);
    await expect(waitMailpitCode(request, quiet, 3_000)).rejects.toThrow(/timed out/);

    // Save SMTP on the page: the next sign-up mails a code with no restart.
    await saveEmail(page, "smtp");
    await expect(page.getByTestId("delivery-summary")).toContainText("email=smtp");
    const loud = `delivery-loud-${Date.now()}@example.com`;
    await signupNewUser(guest, loud);
    expect(await waitMailpitCode(request, loud)).toBeTruthy();
    await ctx.close();

    // Text messages: off sends nothing, then saved settings deliver, and a rotated
    // secret keeps delivering.
    await saveSms(page, "off", "");
    await expect(page.getByTestId("delivery-summary")).toContainText("sms=noop");
    await saveSms(page, "verify", "first-secret");
    await expect(page.getByTestId("delivery-summary")).toContainText("sms=http_capture");
    const sendCode = async () => {
      await clearSmsSink(request);
      await page.goto("/user/confirm-account");
      await expect(page.getByTestId("confirm-step-phone")).toBeVisible({ timeout: 60_000 });
      await page.getByTestId("confirm-phone-e164").locator("input").fill("+15555550111");
      await clickTestId(page, "confirm-phone-send");
      return waitSmsOtp(request);
    };
    expect(await sendCode()).toMatch(/^\d{4,8}$/);
    await page.goto("/lab/delivery");
    await saveSms(page, "verify", "rotated-secret");
    await expect(page.getByTestId("delivery-summary")).toContainText("revision=");
    expect(await sendCode()).toMatch(/^\d{4,8}$/);
  });

  test("pw-lepton-delivery-settings-denied-sad", async ({ page, request }) => {
    const { plain, password } = await seedDelivery(request);
    await openDelivery(page, plain, password);
    await expect(page.getByTestId("delivery-error")).toContainText("permission_denied", {
      timeout: 30_000,
    });
    // A save is refused too, and nothing changes.
    await saveEmail(page, "off");
    await expect(page.getByTestId("delivery-error")).toContainText("permission_denied");
    await expect(page.getByTestId("delivery-summary")).not.toContainText("email=noop");
  });

  test("pw-lepton-delivery-settings-invalid-sad", async ({ page, request }) => {
    const { admin, password } = await seedDelivery(request);
    await openDelivery(page, admin, password);
    // SendGrid without a key is refused and the running service stays as it was.
    await saveEmail(page, "sendgrid", { sendgrid: "" });
    await expect(page.getByTestId("delivery-error")).toContainText("invalid");
    await expect(page.getByTestId("delivery-summary")).toContainText("email=smtp");
    // Twilio settings without a secret are refused.
    await saveSms(page, "verify", "");
    await expect(page.getByTestId("delivery-error")).toContainText("twilio_api_secret");
    await expect(page.getByTestId("delivery-summary")).toContainText("sms=http_capture");
  });
});
