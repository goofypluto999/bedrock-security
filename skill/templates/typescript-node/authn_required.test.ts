/**
 * AUTHN-REQUIRED-001 — Every data endpoint requires authentication, the "Postman test" (OWASP API2:2023, A01:2021).
 * Stack: TypeScript/Node (vitest + supertest).
 *
 * PROVE: hit every data endpoint with NO credentials -> must 401/403, NEVER 200-with-data. An open
 * endpoint lets any unauthenticated user query your DB. Enumerate from the route inventory (INV-001)
 * and probe each anonymously; mark genuinely public routes so they're excluded.
 *
 * Wire the TODOs: build `app` and paste the real route inventory into DATA_ROUTES / PUBLIC.
 */
import { describe, it, expect } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

// TODO: paste the route inventory from the frame stage. Every route that reads/mutates data.
const DATA_ROUTES: [string, string][] = [
  ["get", "/api/users"],
  ["get", "/api/users/1"],
  ["get", "/api/orders"],
  ["post", "/api/orders"],
  ["get", "/api/me"],
];
// Genuinely public routes (login, signup, health, public landing data) — excluded from the deny check.
const PUBLIC = new Set(["POST /api/login", "POST /api/signup", "GET /health"]);

const probeable = DATA_ROUTES.filter(([m, p]) => !PUBLIC.has(`${m.toUpperCase()} ${p}`));

describe("AUTHN-REQUIRED-001 unauthenticated-request test", () => {
  it.each(probeable)("%s %s rejects an anonymous request", async (method, path) => {
    const resp = await (request(app) as any)[method](path); // deliberately NO Authorization header
    expect([401, 403]).toContain(resp.status); // never 200-with-data
    if (resp.status === 200) {
      expect(resp.body, `${method} ${path} returned data without auth`).toBeFalsy();
    }
  });

  it("public routes remain reachable (over-correction guard)", async () => {
    for (const sig of PUBLIC) {
      const [method, path] = sig.split(" ");
      if (method === "GET") {
        const resp = await (request(app) as any).get(path);
        expect(resp.status).toBeLessThan(500);
      }
    }
  });
});
