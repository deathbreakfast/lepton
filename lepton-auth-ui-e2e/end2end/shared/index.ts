/**
 * Shared Playwright helpers for Lepton auth UI e2e.
 *
 * Product hosts can copy or import from this folder (path relative to the
 * harness). Seed scenarios are owned by `lepton-test-support` in Rust.
 */

export { seedTestData, type SeedResult } from "./seed";
export { clearMailpit, waitMailpitCode } from "./mail";
export { clearSmsSink, waitSmsOtp } from "./sms";
export {
  authDialog,
  clickTestId,
  dismissAuthOverlay,
  installVirtualAuthenticator,
  resetDialog,
  seedAndSignIn,
  signInAs,
  signupNewUser,
  submitSignin,
} from "./auth";
