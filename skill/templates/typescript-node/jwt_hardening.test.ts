/**
 * JWT-001 — JWT decode rejects none/confusion/missing-exp/expired/tampered/aud (RFC 8725).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: six abusive token classes — alg=none, alg-confusion (RS→HS w/ public key as HMAC secret),
 * missing-exp, expired, tampered-signature, aud-mismatch — ALL return 401 on a protected route.
 *
 * Wire the TODOs: how you build `app`, the secrets/keys the app verifies with, and a protected route.
 */
import { describe, it, expect } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

const PROTECTED = "/api/me"; // TODO: any route requiring a valid access token
const HS_SECRET = "test-only-hmac-secret"; // TODO: the HS256 secret the app verifies with (test value)
const RS_PUBLIC = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"; // TODO: the app's RS256 public key (PEM)
const AUD = "marr-api"; // TODO: the audience the app requires
const sub = "user-1";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// Each entry crafts ONE malformed/abusive token. None should authenticate.
const ATTACKS: [string, string][] = [
  ["alg=none", jwt.sign({ sub, aud: AUD }, "", { algorithm: "none" as any, expiresIn: "1h" })],
  ["alg-confusion RS→HS", jwt.sign({ sub, aud: AUD, exp: Math.floor(Date.now() / 1e3) + 3600 }, RS_PUBLIC, { algorithm: "HS256" })],
  ["missing exp", jwt.sign({ sub, aud: AUD }, HS_SECRET, { algorithm: "HS256", noTimestamp: true })],
  ["expired", jwt.sign({ sub, aud: AUD }, HS_SECRET, { algorithm: "HS256", expiresIn: -10 })],
  ["aud mismatch", jwt.sign({ sub, aud: "some-other-api", exp: Math.floor(Date.now() / 1e3) + 3600 }, HS_SECRET, { algorithm: "HS256" })],
];

describe("JWT-001 JWT hardening", () => {
  it.each(ATTACKS)("rejects %s with 401", async (_label, tok) => {
    const resp = await request(app).get(PROTECTED).set(bearer(tok));
    expect(resp.status).toBe(401); // never 200; a single accepted forgery is total auth bypass
  });

  it("rejects a tampered signature with 401", async () => {
    const good = jwt.sign({ sub, aud: AUD, exp: Math.floor(Date.now() / 1e3) + 3600 }, HS_SECRET, { algorithm: "HS256" });
    const parts = good.split("."); parts[2] = parts[2].slice(0, -2) + "xx"; // corrupt the signature
    const resp = await request(app).get(PROTECTED).set(bearer(parts.join(".")));
    expect(resp.status).toBe(401);
  });

  it("accepts a correctly-signed, current, right-aud token (no over-correction)", async () => {
    const valid = jwt.sign({ sub, aud: AUD, exp: Math.floor(Date.now() / 1e3) + 3600 }, HS_SECRET, { algorithm: "HS256" });
    const resp = await request(app).get(PROTECTED).set(bearer(valid));
    expect(resp.status).toBe(200);
  });
});
