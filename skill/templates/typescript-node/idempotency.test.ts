/**
 * IDEM-001 — Idempotency: a retried non-idempotent op applies its effect exactly once (logic; companion to RACE-001).
 * Stack: TypeScript/Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: the SAME Idempotency-Key sent twice — sequentially AND concurrently via Promise.all —
 * produces the side effect exactly once, and both responses are identical (stored result replayed).
 *
 * Wire the TODOs: build `app`, log in, pick a non-idempotent route, and count the side effect.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = "";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// TODO: a non-idempotent op a client may retry (charge / create_order / send_email).
const ROUTE = "/api/payments/charge";
const BODY = { amount: 4200, currency: "usd" };

// TODO: return how many times the real side effect occurred for `key` (DB rows, charges, sends).
async function sideEffectCount(_key: string): Promise<number> {
  throw new Error("wire sideEffectCount(): count charges/orders/emails for this key");
}

beforeAll(async () => {
  // token = await login("payer@example.com");
});

const fire = (key: string) => request(app).post(ROUTE).set(bearer(token)).set("Idempotency-Key", key).send(BODY);

describe("IDEM-001 idempotent retry", () => {
  it("sequential duplicate key -> effect once, responses match", async () => {
    const key = `seq-${Date.now()}`;
    const first = await fire(key);
    const second = await fire(key);
    expect([200, 201]).toContain(first.status);
    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body); // replayed stored result, not a re-execution
    expect(await sideEffectCount(key)).toBe(1);
  });

  it("concurrent duplicate key (Promise.all) -> still exactly one effect", async () => {
    const key = `conc-${Date.now()}`;
    const results = await Promise.all(Array.from({ length: 8 }, () => fire(key)));
    results.forEach((r) => expect([200, 201, 409]).toContain(r.status)); // 409 acceptable for losers
    expect(await sideEffectCount(key)).toBe(1); // the whole point — race must not double-charge
  });
});
