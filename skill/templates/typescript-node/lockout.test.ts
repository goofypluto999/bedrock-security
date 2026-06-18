/**
 * LOCK-001 — Per-account lockout at threshold, before the password hash (OWASP API4:2023, ASVS V2.2.1).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: N failed logins on ONE email from MANY different IPs (with VALID-SHAPED wrong passwords,
 * so input validation doesn't mask the test) are throttled by IDENTITY — not just per-IP.
 *
 * Wire the TODOs: how you build `app`, the LOGIN route, the THRESHOLD, and a known email.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

const LOGIN = "/api/auth/login"; // TODO
const THRESHOLD = 5; // TODO: the documented failed-attempt threshold per account
const EMAIL = "victim@example.com"; // TODO: a real, registered account
const WRONG = "Wrong-Passw0rd!"; // valid-SHAPED (meets policy) but incorrect — avoids 400 validation masking

beforeAll(async () => {
  // TODO: ensure EMAIL exists so we exercise the lockout path, not "unknown user".
});

describe("LOCK-001 per-account lockout by identity", () => {
  it("throttles the account after the threshold even when each attempt comes from a new IP", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < THRESHOLD + 2; i++) {
      const resp = await request(app)
        .post(LOGIN)
        .set("X-Forwarded-For", `203.0.113.${i}`) // every attempt from a different source IP
        .send({ email: EMAIL, password: WRONG });
      statuses.push(resp.status);
    }
    // Per-IP limiting would let all of these through; identity-keyed lockout must bite.
    const throttled = statuses.slice(THRESHOLD).some((s) => s === 429 || s === 423);
    expect(throttled).toBe(true); // locked/too-many by identity (429 or 423), not an endless 401 stream
    expect(statuses.filter((s) => s === 200).length).toBe(0); // never authenticated with a wrong password
  });

  it("a different, untargeted account can still log in (no over-correction / global lock)", async () => {
    // TODO: use a real other account + its correct password.
    const resp = await request(app).post(LOGIN).send({ email: "bystander@example.com", password: "Correct-Passw0rd!" });
    expect(resp.status).not.toBe(429);
    expect(resp.status).not.toBe(423);
  });
});
