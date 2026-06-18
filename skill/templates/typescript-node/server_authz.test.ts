/**
 * AUTHZ-SERVER-001 — Authorization enforced server-side, no client-only role checks (OWASP A01:2021, API5:2023, CWE-602).
 * Stack: TypeScript/Node (vitest + supertest). Companion to BFLA-001.
 *
 * PROVE: a client-side `if (user.isAdmin)` only HIDES the button. Call every privileged endpoint
 * directly with a crafted request from a NON-admin (but valid) token — bypassing all UI gating —
 * and it must 403, regardless of what the UI would show. Client checks are UX, never the gate.
 *
 * Wire the TODOs: build `app`, mint a valid non-admin token, and list the privileged routes.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let userToken = ""; // a VALID, authenticated, NON-privileged user
let adminToken = ""; // a real admin — proves we're not just blanket-denying
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

beforeAll(async () => {
  // userToken = await login("plain@example.com");  // role: user
  // adminToken = await login("boss@example.com");  // role: admin
});

// Privileged endpoints the UI hides behind a role check. method, path, body.
const PRIVILEGED: [string, string, any][] = [
  ["get", "/api/admin/users", undefined],
  ["post", "/api/admin/users/42/ban", {}],
  ["delete", "/api/admin/flags/7", undefined],
  ["patch", "/api/admin/settings", { featureFlag: true }],
];

describe("AUTHZ-SERVER-001 server-side authorization", () => {
  it.each(PRIVILEGED)("%s %s -> 403 for a valid non-admin (UI gating bypassed)", async (method, path, body) => {
    const resp = await (request(app) as any)[method](path).set(bearer(userToken)).send(body);
    expect(resp.status).toBe(403); // server re-checks role; client-only hiding is not trusted
    expect(resp.status).not.toBe(200); // 200 here = privileged data reachable by a normal user
  });

  it("an actual admin still reaches a privileged endpoint (no over-correction)", async () => {
    const resp = await request(app).get("/api/admin/users").set(bearer(adminToken));
    expect(resp.status).toBe(200);
  });
});
