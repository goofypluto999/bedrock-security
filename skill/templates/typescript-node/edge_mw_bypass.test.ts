/**
 * EDGE-MW-001 — Edge / Next middleware auth cannot be bypassed (matcher / casing / rewrite) (OWASP API1:2023, CWE-287).
 * Stack: TypeScript / Node (vitest + supertest). Works for Next.js middleware.ts / edge functions.
 *
 * PROVE: an unauthenticated client hitting any bypass variant of a protected route — casing, trailing
 * slash, percent-encoded traversal, double slash, known rewrite target — is ALWAYS blocked (redirect
 * or 401), never served protected content (200). An authenticated client still reaches the route.
 *
 * Wire the TODOs: the Next.js handler shim, a valid auth cookie, and the exact protected path.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler (the Next.js request handler or equivalent).
// import { app } from "../../src/app";
const app: any = null; // TODO

// TODO: obtain a valid session cookie for an authenticated test user.
let authCookie = ""; // e.g. "next-auth.session-token=<value>"

// TODO: the canonical protected path your middleware guards (lowercase, no trailing slash).
const PROTECTED_CANONICAL = "/dashboard";

// Bypass variants an adversary would try against a Next.js matcher.
// Each entry: [label, path]. Add project-specific rewrites / aliases as needed.
const BYPASS_VARIANTS: [string, string][] = [
  ["uppercase first letter",      "/Dashboard"],
  ["all caps",                     "/DASHBOARD"],
  ["trailing slash",               "/dashboard/"],
  ["double leading slash",         "//dashboard"],
  ["percent-encoded dot-dot",      "/%2e%2e/dashboard"],
  ["encoded slash",                "/dashboard%2F"],
  ["null byte suffix",             "/dashboard%00"],
  ["semicolon suffix",             "/dashboard;"],
  // TODO: add any internal rewrite targets that resolve to the same handler
  // e.g. ["internal rewrite target", "/_next/data/xxxx/dashboard.json"],
];

beforeAll(async () => {
  // TODO: sign in a test user and capture the auth cookie.
  // const r = await request(app).post("/api/auth/signin").send({ email: "test@example.com", password: "..." });
  // authCookie = r.headers["set-cookie"]?.[0] ?? "";
});

describe("EDGE-MW-001 middleware bypass variants are all blocked for unauthenticated clients", () => {
  it.each(BYPASS_VARIANTS)(
    "variant '%s' (%s) is blocked (redirect or 401), never 200 with content",
    async (_label, path) => {
      const resp = await request(app).get(path);
      // Must be a redirect to login OR an explicit 401/403 — never 200 with protected content.
      const isBlocked =
        [301, 302, 307, 308, 401, 403].includes(resp.status) ||
        (resp.status === 200 && !looksLikeProtectedContent(resp.text));
      expect(
        isBlocked,
        `Unauthed request to bypass variant "${path}" returned status ${resp.status} — middleware may be bypassable`
      ).toBe(true);
      // Hard guard: a 200 with any protected content marker is always a fail.
      if (resp.status === 200) {
        expect(resp.text, `Protected content served to unauthed request on path "${path}"`).not.toMatch(
          PROTECTED_CONTENT_MARKER
        );
      }
    }
  );

  it("canonical protected route is blocked without auth", async () => {
    const resp = await request(app).get(PROTECTED_CANONICAL);
    expect([301, 302, 307, 308, 401, 403]).toContain(resp.status);
  });

  it("canonical protected route is accessible with valid auth (no over-correction)", async () => {
    const resp = await request(app)
      .get(PROTECTED_CANONICAL)
      .set("Cookie", authCookie);
    // Authenticated user must reach the page — middleware must not block legitimate traffic.
    expect(resp.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// TODO: replace this with a string / pattern unique to your protected page's
// rendered HTML (e.g. a data-testid, a heading, or a JS variable name).
// ---------------------------------------------------------------------------
const PROTECTED_CONTENT_MARKER = /data-page="dashboard"|__NEXT_DATA__.*dashboard/i;

function looksLikeProtectedContent(body: string): boolean {
  return PROTECTED_CONTENT_MARKER.test(body);
}
