/**
 * INJ-001 — Injection: SQL/XSS/cmd in every string field is neutralized (OWASP A03:2021, CWE-89/79/78).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: hostile payloads in EVERY string field are parameterized/escaped — no 500 with a DB error
 * leak, no executable reflection, and the JSON response stays application/json (stored payload inert).
 *
 * Wire the TODOs: how you build `app`, an authed token, and a write+read route pair with string fields.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = "";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

const WRITE = "/api/notes"; // TODO: a route that persists string fields
const FIELDS = ["title", "body"]; // TODO: every string field the route accepts

const PAYLOADS = [
  "' OR '1'='1",                       // SQL boolean
  "'; DROP TABLE notes; --",           // SQL stacked
  "<script>alert(1)</script>",         // XSS
  "${process.env.SECRET}",             // template-injection probe
  "$(rm -rf /)`reboot`",               // OS command metacharacters
];

beforeAll(async () => {
  // TODO: log in and capture a token.
  // token = await login("user@example.com");
});

describe("INJ-001 injection handling", () => {
  for (const field of FIELDS) {
    it.each(PAYLOADS)(`field "${field}" survives payload %s without 500/DB-leak`, async (payload) => {
      const resp = await request(app).post(WRITE).set(bearer(token)).send({ [field]: payload });
      // Accepted-and-escaped OR cleanly rejected (4xx) — but NEVER a 500 from a broken query.
      expect(resp.status).not.toBe(500);
      const text = JSON.stringify(resp.body).toLowerCase();
      // No DB internals leaking through an error body (the tell of unparameterized SQL).
      expect(text).not.toMatch(/sql|syntax error|sqlstate|econnrefused|relation .* does not exist/);
      if (resp.status < 300 && resp.body && field in resp.body) {
        // If echoed back, it must be stored verbatim (escaped on output), not interpreted.
        expect(resp.body[field]).toBe(payload);
        expect((resp.headers["content-type"] || "")).toContain("application/json"); // inert, not text/html
      }
    });
  }
});
