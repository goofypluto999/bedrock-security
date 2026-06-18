/**
 * WEBHOOK-001 — Inbound webhook verified: HMAC over raw body, replay window, idempotent (OWASP A08:2021).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: bad/missing signature → 400; replayed OLD timestamp → rejected; duplicate event id → processed
 * ONCE. The HMAC must be computed over the RAW request bytes, not a re-serialized JSON object.
 *
 * Wire the TODOs: how you build `app`, the webhook route, the signing secret, and the header/scheme.
 */
import { describe, it, expect } from "vitest";
import crypto from "crypto";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

const HOOK = "/api/webhooks/stripe"; // TODO
const SECRET = "whsec_test_only"; // TODO: the provider signing secret (test value)
const SIG_HEADER = "x-signature"; // TODO: the header the app reads (e.g. Stripe-Signature)
const now = () => Math.floor(Date.now() / 1000);

// TODO: match your provider's exact signing scheme (here: HMAC-SHA256 over `${ts}.${rawBody}`).
const sign = (rawBody: string, ts: number) =>
  `t=${ts},v1=${crypto.createHmac("sha256", SECRET).update(`${ts}.${rawBody}`).digest("hex")}`;

const event = (id: string) => JSON.stringify({ id, type: "payment.succeeded", data: {} });
const send = (raw: string, sig?: string) => {
  const r = request(app).post(HOOK).set("Content-Type", "application/json");
  if (sig) r.set(SIG_HEADER, sig);
  return r.send(raw); // send the RAW string so the server hashes the exact bytes it received
};

describe("WEBHOOK-001 inbound webhook verification", () => {
  it("rejects a missing signature with 400", async () => {
    const resp = await send(event("evt_1"));
    expect(resp.status).toBe(400);
  });

  it("rejects a bad/forged signature with 400", async () => {
    const resp = await send(event("evt_2"), `t=${now()},v1=deadbeef`);
    expect(resp.status).toBe(400);
  });

  it("rejects a replayed old timestamp even if the HMAC matches that timestamp", async () => {
    const raw = event("evt_3"); const old = now() - 60 * 60; // 1h outside any sane tolerance
    const resp = await send(raw, sign(raw, old));
    expect(resp.status).toBe(400); // signature is valid for `old`, but the timestamp is stale
  });

  it("processes a duplicate event id exactly once (idempotent)", async () => {
    const raw = event("evt_dup"); const ts = now(); const sig = sign(raw, ts);
    const first = await send(raw, sig);
    const second = await send(raw, sig);
    expect(first.status).toBeLessThan(300); // accepted once
    // The second must NOT re-run the side effect: deduped (e.g. 409) or an idempotent 200 no-op.
    expect([200, 409]).toContain(second.status);
    // TODO: assert the side effect (charge applied / row inserted) happened exactly ONCE.
  });
});
