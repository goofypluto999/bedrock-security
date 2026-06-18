/**
 * SSRF-001 — Server fetch validates resolved IP and re-validates redirects (CWE-918, OWASP A10:2021).
 * Stack: TypeScript / Node (vitest + supertest). Works for Express/Fastify/Next API routes.
 *
 * PROVE: a user-supplied URL pointing at metadata (169.254.169.254), 127.0.0.1, a private range,
 * AND a public URL that 302-redirects to a private one are ALL rejected — only allow-listed hosts pass.
 *
 * Wire the TODOs: how you build `app`, an authed token, the URL-consuming route, and a redirect fixture.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let token = "";
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// TODO: a route that fetches a user-influenced URL (import-from-URL, avatar-by-URL, webhook reg, unfurl).
const FETCH = "/api/import";
const urlField = (u: string) => ({ url: u });

// TODO: stand up (or point at) a PUBLIC endpoint you control that 302-redirects to 127.0.0.1.
const PUBLIC_REDIRECT_TO_PRIVATE = "http://example.com/redirect-to-localhost";

const BLOCKED = [
  "http://169.254.169.254/latest/meta-data/",   // cloud metadata — the crown jewels
  "http://127.0.0.1:6379/",                       // loopback (e.g. redis)
  "http://localhost/admin",                       // loopback by name (DNS → 127.0.0.1)
  "http://10.0.0.1/",                             // RFC1918 private
  "http://192.168.0.1/",                          // RFC1918 private
  "http://[::1]/",                                // IPv6 loopback
  "file:///etc/passwd",                           // non-http scheme
  PUBLIC_REDIRECT_TO_PRIVATE,                      // validate AFTER resolution + on EVERY redirect hop
];

beforeAll(async () => {
  // TODO: log in and capture a token.
  // token = await login("user@example.com");
});

describe("SSRF-001 server-side request forgery", () => {
  it.each(BLOCKED)("rejects fetch to %s", async (u) => {
    const resp = await request(app).post(FETCH).set(bearer(token)).send(urlField(u));
    expect(resp.status).toBeGreaterThanOrEqual(400); // rejected — never silently fetched
    expect(resp.status).toBeLessThan(500); // a clean 400/422, not a 500 that proves it tried to connect
  });

  it("allows an allow-listed public URL (no over-correction)", async () => {
    // TODO: replace with a host that is genuinely on your allow-list.
    const resp = await request(app).post(FETCH).set(bearer(token)).send(urlField("https://allowed.example.com/ok"));
    expect(resp.status).toBeLessThan(400);
  });
});
