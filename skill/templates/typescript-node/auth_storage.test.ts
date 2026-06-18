/**
 * AUTH-STORAGE-001 — Auth token/session not stored in localStorage/sessionStorage (CWE-922, OWASP A07:2021).
 * Stack: TypeScript/Node (vitest + fetch + jsdom-style storage probe). Runs against the running app.
 *
 * PROVE: after login, no auth token/PII lands in localStorage/sessionStorage (XSS-readable); the token
 * lives in an HttpOnly+Secure+SameSite cookie (or memory only). A token in web storage is readable by
 * any injected script — the cookie must be HttpOnly so JS cannot reach it.
 *
 * Wire the TODOs: set APP_URL, the login route, and replay login through a Storage shim.
 */
import { describe, it, expect, beforeAll } from "vitest";

const APP_URL = process.env.APP_URL ?? "http://localhost:3000"; // TODO
const LOGIN = "/api/login"; // TODO

const TOKENISH = /(token|jwt|access|refresh|session|auth|email|phone)/i;
const store: Record<string, string> = {};
let setCookie = "";

beforeAll(async () => {
  // Capture what the login flow tries to persist. TODO: if your client SDK writes storage,
  // run it here against a Storage shim; otherwise this asserts the SERVER sets an HttpOnly cookie.
  const res = await fetch(`${APP_URL}${LOGIN}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "a@example.com", password: "correct horse battery" }), // TODO creds
  });
  setCookie = res.headers.get("set-cookie") ?? "";
});

describe("AUTH-STORAGE-001 client-side auth storage", () => {
  it("nothing auth/PII-shaped was written to local/sessionStorage", () => {
    const offenders = Object.keys(store).filter((k) => TOKENISH.test(k) || TOKENISH.test(store[k]));
    expect(offenders, `auth/PII written to web storage: ${offenders.join(", ")}`).toHaveLength(0);
  });

  it("the session cookie is HttpOnly + Secure + SameSite", () => {
    expect(setCookie, "login set no cookie — token is presumably in JS-readable storage").not.toBe("");
    expect(/HttpOnly/i.test(setCookie), "session cookie missing HttpOnly (XSS can read it)").toBe(true);
    expect(/Secure/i.test(setCookie)).toBe(true);
    expect(/SameSite/i.test(setCookie)).toBe(true);
  });
});
