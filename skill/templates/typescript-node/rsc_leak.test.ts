/**
 * NEXT-RSC-001 — React Server Component leaks DB objects / PII to the client (OWASP API3:2023, CWE-200).
 * Stack: TypeScript / Node (vitest + supertest). Works for Next.js App Router (RSC) pages.
 *
 * PROVE: the serialised RSC flight payload (`self.__next_f` / `__RSC_MANIFEST`) delivered with a
 * logged-in page response contains ONLY the explicit DTO fields, not raw DB columns — no password
 * hash, no internal flags, no other-user PII, no secrets.
 *
 * Wire the TODOs: the Next.js handler / supertest shim, a valid session cookie, and the sentinel
 * field names that must never appear in the serialised payload.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler (e.g. the Next.js request handler).
// import { app } from "../../src/app";
const app: any = null; // TODO

// TODO: obtain a real session cookie for a logged-in test user.
let sessionCookie = ""; // e.g. "next-auth.session-token=<value>"

// TODO: the route that renders a server component that fetches a user/resource from the DB.
const PROTECTED_PAGE = "/dashboard"; // TODO

// Fields that MUST NEVER appear in the RSC flight payload.
// These are raw DB column names or internal fields that should be stripped to a DTO.
const FORBIDDEN_FIELD_PATTERNS: RegExp[] = [
  /password_hash/i,    // TODO: add your actual raw column names
  /hashed_password/i,
  /internal_flag/i,
  /"role"\s*:\s*"(admin|superuser|internal)"/i,
  /stripe_customer_id/i,
  /api_secret/i,
  // TODO: add any other raw DB columns that must not cross the server→client boundary
];

// Fields that MUST be present (prove the DTO itself is serialised — no false positive).
const REQUIRED_DTO_FIELDS: string[] = [
  "id",      // TODO: replace with the actual DTO fields the client component legitimately needs
  "name",
];

beforeAll(async () => {
  // TODO: sign in a test user and capture the session cookie.
  // const r = await request(app).post("/api/auth/signin").send({ email: "test@example.com", password: "..." });
  // sessionCookie = r.headers["set-cookie"]?.[0] ?? "";
});

describe("NEXT-RSC-001 RSC flight payload does not leak raw DB fields", () => {
  it("flight payload contains no forbidden raw-DB / sensitive fields", async () => {
    const resp = await request(app)
      .get(PROTECTED_PAGE)
      .set("Cookie", sessionCookie)
      .set("Accept", "text/html");

    expect(resp.status).toBe(200);
    const html: string = resp.text;

    // Locate the RSC flight data — Next.js inlines it as self.__next_f push calls.
    const flightBlocks = [...html.matchAll(/self\.__next_f\.push\(\[1,\s*"(.*?)"\]\)/gs)].map(
      (m) => m[1] ?? ""
    );
    const rawFlight = flightBlocks.join("\n");

    // Assert no forbidden field leaks into the serialised payload.
    for (const pattern of FORBIDDEN_FIELD_PATTERNS) {
      expect(
        rawFlight,
        `Forbidden field matching ${pattern} found in RSC flight payload`
      ).not.toMatch(pattern);
    }
  });

  it("flight payload DOES contain the expected DTO fields (no false positive)", async () => {
    const resp = await request(app)
      .get(PROTECTED_PAGE)
      .set("Cookie", sessionCookie)
      .set("Accept", "text/html");

    expect(resp.status).toBe(200);
    const html: string = resp.text;
    const flightBlocks = [...html.matchAll(/self\.__next_f\.push\(\[1,\s*"(.*?)"\]\)/gs)].map(
      (m) => m[1] ?? ""
    );
    const rawFlight = flightBlocks.join("\n");

    // Prove the DTO itself is serialised — if NONE of the expected fields appear,
    // the test above is vacuously passing (the page may not be fetching anything at all).
    const anyDtoFieldPresent = REQUIRED_DTO_FIELDS.some((f) => rawFlight.includes(`"${f}"`));
    expect(
      anyDtoFieldPresent,
      "No expected DTO field found in RSC flight payload — wire REQUIRED_DTO_FIELDS to your real DTO"
    ).toBe(true);
  });

  it("unauthenticated request is redirected / gated (no RSC data at all)", async () => {
    const resp = await request(app).get(PROTECTED_PAGE).set("Accept", "text/html");
    // Must redirect to login or return 401 — must NOT serve RSC payload with any user data.
    expect([301, 302, 307, 308, 401]).toContain(resp.status);
    if (resp.text) {
      expect(resp.text).not.toMatch(/self\.__next_f/);
    }
  });
});
