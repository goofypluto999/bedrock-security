/**
 * BFLA-001 — Function authz: lower-role token cannot reach admin/owner routes (OWASP API5:2023).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: a VALID, authenticated LOWER-role token (a normal user) is rejected with 403 on
 * EVERY admin/owner-only route and method — function-level authz, not just "is logged in".
 *
 * Wire the TODOs: how you build `app`, and mint a real low-role token + a real admin token.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let userToken = ""; // a valid, authenticated NON-admin (lowest privilege you mint)
let adminToken = ""; // a valid admin/owner — only to prove the route works (no over-correction)

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

beforeAll(async () => {
  // TODO: log in two identities of DIFFERENT roles and capture their tokens.
  // userToken = await login("user@example.com");   // role: user
  // adminToken = await login("admin@example.com");  // role: admin/owner
});

// Every admin/owner-gated route — include the mutating ones; method matters.
const PRIVILEGED: [string, string, any][] = [
  ["get", "/api/admin/users", undefined],
  ["post", "/api/admin/users", { email: "x@x.io", role: "admin" }],
  ["delete", "/api/admin/users/1", undefined],
  ["post", "/api/admin/feature-flags", { flag: "x", on: true }],
];

describe("BFLA-001 function-level authorization", () => {
  it.each(PRIVILEGED)("%s %s rejects a valid lower-role token with 403", async (method, path, body) => {
    const resp = await (request(app) as any)[method](path).set(bearer(userToken)).send(body);
    expect(resp.status).toBe(403); // valid token, wrong role → forbidden (NOT 401, NOT 200, NOT 404-hide)
    expect(resp.status).not.toBe(200); // a 200 here is a privilege escalation
  });

  it.each(PRIVILEGED)("%s %s still works for an admin (no over-correction)", async (method, path, body) => {
    const resp = await (request(app) as any)[method](path).set(bearer(adminToken)).send(body);
    expect(resp.status).toBeLessThan(400); // admin path must remain functional
  });
});
