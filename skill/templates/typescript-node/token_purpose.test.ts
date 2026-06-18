/**
 * JWT-002 — Token-purpose confusion: non-access tokens rejected on protected routes (OWASP API2:2023, RFC 8725 §3.11).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: each non-access token type (2fa_challenge, pw_reset, email_verify) used as a Bearer on a
 * protected route → 401. Crucially the 2FA challenge token from /login CANNOT authenticate (the 2FA bypass).
 *
 * Wire the TODOs: how you build `app`, mint each purpose-stamped token, and a protected route.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

const PROTECTED = "/api/me"; // TODO: any route requiring a real ACCESS token
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// TODO: mint each token via the SAME signer the app uses, stamped with its real `purpose` claim.
// These must be otherwise-valid (correct alg, unexpired) so we prove PURPOSE is enforced, not just signature.
const nonAccess: Record<string, string> = {
  twofa_challenge: "", // TODO: the token /login returns BEFORE the 2FA code is verified
  pw_reset: "",        // TODO: the token emailed for password reset
  email_verify: "",    // TODO: the token emailed to verify an address
};

let challengeFromLogin = ""; // TODO: capture the exact challenge token /login hands back

beforeAll(async () => {
  // TODO: mint each non-access token; complete step 1 of /login (pre-2FA) and capture its challenge token.
  // const r = await request(app).post("/api/auth/login").send({ email, password }); challengeFromLogin = r.body.challenge_token;
});

describe("JWT-002 token-purpose confusion", () => {
  it.each(Object.entries(nonAccess))("rejects a %s token as Bearer with 401", async (_purpose, tok) => {
    const resp = await request(app).get(PROTECTED).set(bearer(tok));
    expect(resp.status).toBe(401); // valid signature, wrong PURPOSE → must not authenticate
  });

  it("the 2FA challenge token from /login cannot authenticate a protected route (the 2FA bypass)", async () => {
    const resp = await request(app).get(PROTECTED).set(bearer(challengeFromLogin));
    expect(resp.status).toBe(401); // a 200 here means 2FA is bypassable by replaying the challenge token
    expect(resp.status).not.toBe(200);
  });
});
