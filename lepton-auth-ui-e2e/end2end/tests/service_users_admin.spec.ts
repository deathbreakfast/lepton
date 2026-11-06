import { test, expect, signInAs } from "./fixtures";

type Seeded = {
  password: string;
  owner_ids: string[];
  tag: string;
  admin: string;
  plain: string;
  handles: [string[], string[]];
};

async function seedServiceUsers(
  request: import("@playwright/test").APIRequestContext,
): Promise<Seeded> {
  const tag = `${Date.now()}${Math.floor(Math.random() * 1000)}`;
  const admin = `su-admin-${tag}@example.com`;
  const plain = `su-plain-${tag}@example.com`;
  const handles: [string[], string[]] = [
    [`spectra-agent-${tag}`, `mail-bot-${tag}`],
    [`billing-bot-${tag}`],
  ];
  const res = await request.post("/api/test/seed-service-users", {
    data: {
      admin_email: admin,
      owners: [
        { email: plain, handles: handles[0] },
        { email: `su-other-${tag}@example.com`, handles: handles[1] },
      ],
    },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  const body = (await res.json()) as { password: string; owner_ids: string[] };
  return { ...body, tag, admin, plain, handles };
}

async function openAllServiceUsers(
  page: import("@playwright/test").Page,
  email: string,
  password: string,
) {
  await signInAs(page, email, password, "/welcome");
  await expect(page).toHaveURL(/\/welcome/, { timeout: 60_000 });
  await page.goto("/user/bots/all");
  await expect(page.getByTestId("all-service-users-page")).toBeVisible({
    timeout: 60_000,
  });
}

test.describe("pw-service-users-admin all service users page", () => {
  test("all_service_users_requires_auth_sad", async ({ page }) => {
    await page.goto("/user/bots/all");
    await expect(page.getByTestId("all-service-users-error")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("all-service-users-error")).toContainText(
      /signed in/i,
    );
    await expect(page.getByTestId("all-service-users-row")).toHaveCount(0);
  });

  test("all_service_users_forbidden_for_non_admin_sad", async ({
    page,
    request,
  }) => {
    const seeded = await seedServiceUsers(request);
    await openAllServiceUsers(page, seeded.plain, seeded.password);
    await expect(page.getByTestId("all-service-users-error")).toContainText(
      /not allowed/i,
      { timeout: 30_000 },
    );
    await expect(page.getByTestId("all-service-users-row")).toHaveCount(0);
  });

  test("all_service_users_lists_every_owner_happy", async ({
    page,
    request,
  }) => {
    const seeded = await seedServiceUsers(request);
    await openAllServiceUsers(page, seeded.admin, seeded.password);
    // The host is shared across tests, so narrow to this test's own handles.
    await expect(page.getByTestId("all-service-users-list")).toBeVisible({
      timeout: 30_000,
    });
    await page
      .getByTestId("all-service-users-filter")
      .locator("input")
      .fill(seeded.tag);
    const rows = page.getByTestId("all-service-users-row");
    await expect(rows).toHaveCount(3, { timeout: 30_000 });
    for (const handle of [...seeded.handles[0], ...seeded.handles[1]]) {
      await expect(
        page.getByTestId("all-service-users-handle").filter({ hasText: handle }),
      ).toBeVisible();
    }
    const owners = page.getByTestId("all-service-users-owner");
    await expect(
      owners.filter({ hasText: seeded.owner_ids[0] }),
    ).toHaveCount(2);
    await expect(
      owners.filter({ hasText: seeded.owner_ids[1] }),
    ).toHaveCount(1);
  });

  test("all_service_users_handle_filter_happy", async ({ page, request }) => {
    const seeded = await seedServiceUsers(request);
    await openAllServiceUsers(page, seeded.admin, seeded.password);
    const rows = page.getByTestId("all-service-users-row");
    const filter = page.getByTestId("all-service-users-filter").locator("input");
    await expect(page.getByTestId("all-service-users-list")).toBeVisible({
      timeout: 30_000,
    });
    await filter.fill(seeded.tag);
    await expect(rows).toHaveCount(3, { timeout: 30_000 });

    // Case and dashes are ignored.
    await filter.fill(`MAILBOT${seeded.tag}`);
    await expect(rows).toHaveCount(1);
    await expect(
      page.getByTestId("all-service-users-handle"),
    ).toContainText(seeded.handles[0][1]);

    await filter.fill("no-such-handle");
    await expect(page.getByTestId("all-service-users-empty")).toBeVisible();
    await expect(rows).toHaveCount(0);

    await filter.fill(seeded.tag);
    await expect(rows).toHaveCount(3);
  });
});
