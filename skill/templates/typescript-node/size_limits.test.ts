/**
 * SIZE-001 — Body size, JSON depth, and decompressed size are bounded (CWE-400).
 * Stack: TypeScript/Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: an oversized body -> 413; an over-deep nested JSON body -> 400 (a clean reject,
 * NOT a 500 / stack-overflow crash). The failure mode under hostile input must be a bounded
 * rejection, never an unhandled crash that takes the process down.
 *
 * Wire the TODOs: build `app`, pick a body-accepting route, and set the real limits.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = "";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

const ROUTE = "/api/items"; // TODO: an endpoint that accepts a JSON body.
const MAX_BYTES = 1_000_000; // TODO: match your configured body limit.

beforeAll(async () => {
  // token = await login("a@example.com");
});

// Build n-deep nested JSON: {"a":{"a":{...}}} — exercises the parser's recursion bound.
const deep = (n: number) => "{\"a\":".repeat(n) + "1" + "}".repeat(n);

describe("SIZE-001 input bounds", () => {
  it("oversized body -> 413", async () => {
    const huge = "x".repeat(MAX_BYTES + 50_000);
    const resp = await request(app).post(ROUTE).set(bearer(token)).set("Content-Type", "application/json").send(JSON.stringify({ blob: huge }));
    expect(resp.status).toBe(413); // Payload Too Large — rejected at the edge/app, not buffered whole
  });

  it("over-deep nested JSON -> 400, never 500/crash", async () => {
    const resp = await request(app).post(ROUTE).set(bearer(token)).set("Content-Type", "application/json").send(deep(5000));
    expect(resp.status).toBe(400); // bounded depth reject
    expect(resp.status).not.toBe(500); // a 500 here means the parser blew the stack — fail
  });

  it("a normal small body still succeeds (no over-correction)", async () => {
    const resp = await request(app).post(ROUTE).set(bearer(token)).send({ name: "ok" });
    expect(resp.status).toBeLessThan(413);
  });
});
