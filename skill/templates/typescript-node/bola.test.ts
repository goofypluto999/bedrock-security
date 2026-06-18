/**
 * BOLA-001 — Object-level authorization (OWASP API1:2023, CWE-639).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: identity B cannot reach A's object by id on ANY read OR write path, and the
 * denial is INDISTINGUISHABLE from "never existed" (same status + body — no 403/404
 * differential that leaks existence).
 *
 * Wire the TODOs: how you build `app`, sign up two users, and create an owned object.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let tokenA = "";
let tokenB = "";
let objectId = "";

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

beforeAll(async () => {
  // TODO: sign up / log in two distinct identities and capture their tokens.
  // tokenA = await login("a@example.com"); tokenB = await login("b@example.com");
  // const r = await request(app).post("/api/objects").set(bearer(tokenA)).send({ name: "secret-A" });
  // objectId = r.body.id;
});

// Every route that takes an owned object id — READ and WRITE. Write paths are the classic miss.
const READ_PATHS = ["/api/objects/:id", "/api/objects/:id/export"];
const WRITE_PATHS: [string, string, any][] = [
  ["post", "/api/objects/:id/comment", { text: "x" }],
  ["delete", "/api/objects/:id", undefined],
];

describe("BOLA-001 object authorization", () => {
  it.each(READ_PATHS)("read %s is an indistinguishable 404 for a non-owner", async (path) => {
    const url = path.replace(":id", objectId);
    const missing = await request(app).get("/api/objects/999999999").set(bearer(tokenB));
    const resp = await request(app).get(url).set(bearer(tokenB));
    expect(resp.status).toBe(404); // never 200 (leak), never 403 (existence oracle)
    expect(resp.status).toBe(missing.status);
    expect(resp.body).toEqual(missing.body); // body must match "never existed"
  });

  it.each(WRITE_PATHS)("%s %s is denied for a non-owner", async (method, path, body) => {
    const url = path.replace(":id", objectId);
    const resp = await (request(app) as any)[method](url).set(bearer(tokenB)).send(body);
    expect(resp.status).toBe(404); // authz-missing-on-write is worse than on read
  });

  it("owner still has access (no over-correction)", async () => {
    const resp = await request(app).get(`/api/objects/${objectId}`).set(bearer(tokenA));
    expect(resp.status).toBe(200);
  });
});
