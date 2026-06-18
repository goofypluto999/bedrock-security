/**
 * RATE-001 — Rate limit holds on authed identity under XFF rotation (OWASP API4:2023, RFC 6585).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: N+1 requests from ONE authenticated identity, each rotating X-Forwarded-For / X-Real-IP,
 * still trip 429 — the limiter keys on identity, not the spoofable client IP. Assert Retry-After.
 *
 * Wire the TODOs: how you build `app`, the LIMIT, and a single authed identity's token.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = "";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

const LIMITED = "/api/expensive"; // TODO: a rate-limited route (auth/LLM/write)
const LIMIT = 5; // TODO: the documented per-identity limit for that route

beforeAll(async () => {
  // TODO: log in one identity and capture the token.
  // token = await login("user@example.com");
});

describe("RATE-001 rate limit under XFF rotation", () => {
  it("returns 429 with Retry-After once the identity limit is exceeded, despite rotating IPs", async () => {
    const statuses: number[] = [];
    let limited: any = null;
    for (let i = 0; i < LIMIT + 1; i++) {
      const resp = await request(app)
        .get(LIMITED)
        .set(bearer(token))
        .set("X-Forwarded-For", `203.0.113.${i}`) // rotate a new spoofed client IP each call
        .set("X-Real-IP", `198.51.100.${i}`);
      statuses.push(resp.status);
      if (resp.status === 429) limited = resp;
    }
    // Spoofing the IP must NOT reset the counter — the (N+1)th still 429s on the same identity.
    expect(statuses).toContain(429);
    expect(limited).not.toBeNull();
    expect(limited.headers["retry-after"]).toBeDefined(); // RFC 6585 — must tell the client when to retry
  });

  it("a fresh identity is not penalized by another's limit (no over-correction)", async () => {
    // TODO: const other = await login("other@example.com");
    const other = token; // TODO: replace with a distinct identity's token
    const resp = await request(app).get(LIMITED).set(bearer(other)).set("X-Forwarded-For", "203.0.113.250");
    expect(resp.status).not.toBe(429);
  });
});
