/**
 * MASS-001 — Mass assignment: privileged fields are ignored, not bound (OWASP API6:2023).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: POST/PATCH with privileged fields (role, plan, isAdmin, tenantId) does NOT bind them;
 * a re-fetch proves the server-controlled fields are unchanged — the client cannot self-promote.
 *
 * Wire the TODOs: how you build `app`, mint a normal-user token, and read back the profile.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = ""; // a normal, non-privileged user
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// TODO: point these at a real write route and its matching read route.
const WRITE = "/api/me"; // e.g. PATCH own profile
const READ = "/api/me";

const PRIVILEGED = { role: "admin", plan: "enterprise", isAdmin: true, tenantId: "other-tenant" };

beforeAll(async () => {
  // TODO: log in a normal user and capture the token.
  // token = await login("user@example.com");
});

describe("MASS-001 mass assignment", () => {
  it("ignores privileged fields and leaves them unchanged on re-fetch", async () => {
    const before = await request(app).get(READ).set(bearer(token));
    expect(before.status).toBe(200);

    // Attack: smuggle privileged fields alongside a legitimate edit.
    const write = await (request(app) as any)
      .patch(WRITE)
      .set(bearer(token))
      .send({ displayName: "Legit Name", ...PRIVILEGED });
    expect([200, 204]).toContain(write.status); // request may succeed — but must IGNORE the bad fields

    const after = await request(app).get(READ).set(bearer(token));
    expect(after.status).toBe(200);
    // The privileged, server-owned fields must be byte-identical to before the attack.
    for (const k of Object.keys(PRIVILEGED)) {
      expect(after.body[k]).toEqual(before.body[k]); // never the attacker-supplied value
    }
    expect(after.body.role).not.toBe("admin"); // explicit: no self-promotion
  });

  it("still applies the legitimate, allow-listed edit (no over-correction)", async () => {
    const after = await request(app).get(READ).set(bearer(token));
    expect(after.body.displayName).toBe("Legit Name");
  });
});
