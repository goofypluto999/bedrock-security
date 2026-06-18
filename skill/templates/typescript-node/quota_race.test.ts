/**
 * RACE-001 — Quota/balance debit is atomic under concurrency (TOCTOU; logic).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: fire the (N+1)th balance-consuming request CONCURRENTLY against a balance of N →
 * EXACTLY N succeed, never N+1, final balance never negative, and the loser gets 402.
 *
 * Wire the TODOs: how you build `app`, the DEBIT route, and seed a balance of exactly N.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = "";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

const DEBIT = "/api/credits/spend"; // TODO: route that debits exactly 1 unit then does work
const BALANCE = "/api/credits"; // TODO: route that returns { balance }
const N = 5; // TODO: seed the account to EXACTLY this many units in beforeAll

beforeAll(async () => {
  // TODO: log in and seed the balance to EXACTLY N (no more) so N+1 forces contention.
  // token = await login("user@example.com"); await seedBalance(N);
});

describe("RACE-001 atomic quota debit", () => {
  it("admits exactly N of N+1 concurrent debits and never goes negative", async () => {
    // Fire all N+1 at once — a check-then-act debit will over-admit here.
    const results = await Promise.all(
      Array.from({ length: N + 1 }, () => request(app).post(DEBIT).set(bearer(token)).send({}))
    );
    const ok = results.filter((r) => r.status >= 200 && r.status < 300).length;
    const denied = results.filter((r) => r.status === 402).length;

    expect(ok).toBe(N); // exactly N winners — not N+1 (over-debit) and not N-1 (lost update)
    expect(denied).toBe(1); // the loser is rejected with 402 Payment Required
    expect(results.some((r) => r.status === 500)).toBe(false); // not a crash/deadlock under load

    const bal = await request(app).get(BALANCE).set(bearer(token));
    expect(bal.body.balance).toBe(0); // exactly drained
    expect(bal.body.balance).toBeGreaterThanOrEqual(0); // NEVER negative
  });
});
