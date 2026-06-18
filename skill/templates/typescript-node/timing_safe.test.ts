/**
 * TIMING-001 — Submitted-secret comparisons are constant-time (CWE-208).
 * Stack: TypeScript/Node (vitest + supertest).
 *
 * PROVE: every attacker-submittable secret compare (api key, reset token, HMAC, TOTP) goes
 * through crypto.timingSafeEqual — assert the CALL/code path, NOT wall-clock timing
 * (timing assertions are flaky in CI and prove nothing under jitter).
 *
 * Wire the TODOs: import the real comparator and point SOURCES at the files that compare secrets.
 */
import { describe, it, expect, vi } from "vitest";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";

// TODO: import the actual function your app uses to verify a submitted secret.
// import { verifySecret } from "../../src/auth/verify";
const verifySecret: (submitted: string, expected: string) => boolean = (() => {
  throw new Error("wire verifySecret(): import your real secret comparator");
}) as any;

// TODO: files whose secret comparisons must be constant-time (auth, webhook HMAC, reset tokens).
const SOURCES = ["src/auth/verify.ts", "src/webhooks/verifyHmac.ts"];

describe("TIMING-001 constant-time secret compare", () => {
  it("verifySecret routes through crypto.timingSafeEqual", () => {
    const spy = vi.spyOn(crypto, "timingSafeEqual");
    const expected = "s3cr3t-token-value";
    verifySecret("wrong-but-same-length-value", expected); // exercise the mismatch path
    expect(spy).toHaveBeenCalled(); // the proof: the compare primitive was actually invoked
    spy.mockRestore();
  });

  it("no raw === / == comparison of secrets in source (the anti-pattern)", () => {
    const bad = /\b(token|api_?key|secret|hmac|signature|otp)\b[^\n]{0,40}={2,3}/i;
    for (const f of SOURCES) {
      const src = readFileSync(f, "utf8");
      expect(bad.test(src), `${f} compares a secret with == / === — use crypto.timingSafeEqual`).toBe(false);
    }
  });

  it("verifySecret still returns true for the correct secret (no over-correction)", () => {
    expect(verifySecret("correct-secret", "correct-secret")).toBe(true);
  });
});
