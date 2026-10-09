import type { LoginProfile } from "./sessions.js";

/**
 * Built-in App Store Connect profile.
 *
 * Selectors come from Apple's long-standing idmsa auth widget (account name
 * field, #sign-in continue, password field) embedded in
 * `#aid-auth-widget-iFrame` from https://idmsa.apple.com on
 * https://appstoreconnect.apple.com/login. They are best-effort and have not
 * been verified against a live Apple account in this repository. Override with
 * SAFE_CONNECT_ASC_* environment variables if Apple's DOM shifts.
 */
export const APP_STORE_CONNECT_PROFILE_ID = "app-store-connect";

const APPLE_ENTRY = "https://appstoreconnect.apple.com/login";
const APPLE_PORTAL = "https://appstoreconnect.apple.com";
const APPLE_IDMSA = "https://idmsa.apple.com";

function selectorEnv(name: string, fallback: string): string {
  const value = process.env[name];
  if (!value) return fallback;
  if (value.length > 512) throw new Error(`invalid ${name}`);
  return value;
}

export function appStoreConnectProfile(): LoginProfile {
  const otpSelector = selectorEnv(
    "SAFE_CONNECT_ASC_OTP_SELECTOR",
    "#char0, #security-code, div.security-code-container, input[autocomplete='one-time-code']",
  );
  const extraOtp = process.env.SAFE_CONNECT_ASC_OTP_SELECTOR
    ? []
    : [
        { origin: APPLE_IDMSA, selector: "#trusted-device", kind: "otp" as const },
        { origin: APPLE_IDMSA, selector: ".si-phone-number", kind: "otp" as const },
      ];
  return {
    id: APP_STORE_CONNECT_PROFILE_ID,
    entryUrl: APPLE_ENTRY,
    portalOrigin: APPLE_PORTAL,
    credentialOrigin: APPLE_IDMSA,
    credentialFrame: "direct-child",
    usernameSelector: selectorEnv("SAFE_CONNECT_ASC_USERNAME_SELECTOR", "#account_name_text_field"),
    usernameNextSelector: selectorEnv("SAFE_CONNECT_ASC_NEXT_SELECTOR", "#sign-in"),
    passwordSelector: selectorEnv("SAFE_CONNECT_ASC_PASSWORD_SELECTOR", "#password_text_field"),
    success: {
      origin: APPLE_PORTAL,
      pathnamePrefix: "/",
      denyPathnames: ["/login"],
      selector: selectorEnv("SAFE_CONNECT_ASC_SUCCESS_SELECTOR", "a[href='/apps'], a[href^='/apps/']"),
    },
    manual: [
      { origin: APPLE_IDMSA, selector: otpSelector, kind: "otp" },
      ...extraOtp,
      { origin: APPLE_IDMSA, selector: "button[data-si-id='passkey'], #passkey-button", kind: "passkey" },
      { origin: APPLE_IDMSA, selector: ".captcha-container, #captcha", kind: "captcha" },
    ],
  };
}

/** Trusted server-side profiles. Agents may select by id only. */
export function builtinProfiles(): LoginProfile[] {
  return [appStoreConnectProfile()];
}
