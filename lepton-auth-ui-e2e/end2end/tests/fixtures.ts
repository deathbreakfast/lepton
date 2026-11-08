/**
 * Harness test fixtures — re-exports [`../shared`](../shared) and the `auth`
 * Playwright fixture used by existing specs.
 */
import { test as base, expect } from "@playwright/test";
import { seedAndSignIn } from "../shared/auth";

export {
  authDialog,
  clearMailpit,
  clearSmsSink,
  clickTestId,
  dismissAuthOverlay,
  installVirtualAuthenticator,
  resetDialog,
  seedTestData,
  signInAs,
  signupNewUser,
  submitSignin,
  waitMailpitCode,
  waitSmsOtp,
  type SeedResult,
} from "../shared";

export const test = base.extend<{
  auth: {
    signIn: (opts: {
      email: string;
      password: string;
      referer?: string;
    }) => Promise<void>;
  };
}>({
  auth: async ({ page, request }, use) => {
    await use({
      async signIn(opts) {
        await seedAndSignIn(page, request, opts);
      },
    });
  },
});

export { expect };
