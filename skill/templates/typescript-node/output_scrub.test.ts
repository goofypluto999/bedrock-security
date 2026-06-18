/**
 * LLM-OUT-001 — LLM output scrub masks secrets and PII (OWASP LLM02:2025, LLM06:2025, CWE-532).
 * Stack: TypeScript/Node (vitest). Pure unit test against your scrubber — no HTTP needed.
 *
 * PROVE: plant secrets/PII in model output -> all masked; clean output -> returned untouched.
 * Reuse the SAME scrubber as your log redactor (single source of truth — drift between the two
 * is how a secret leaks via one path but not the other).
 *
 * Wire the TODO: import the real scrubObject/scrubOutput your app applies before returning model text.
 */
import { describe, it, expect } from "vitest";

// TODO: import the actual scrubber used both for logs and for LLM output.
// import { scrubOutput } from "../../src/security/scrub";
const scrubOutput: (text: string) => string = (() => {
  throw new Error("wire scrubOutput(): import your real secret/PII masker");
}) as any;

// Each planted secret + a regex that must NOT survive in the scrubbed text.
const SECRETS: [string, RegExp][] = [
  ["Your key is sk-ant-api03-AbCdEf0123456789AbCdEf0123456789", /sk-ant-api03-[A-Za-z0-9]/],
  ["AWS creds AKIAIOSFODNN7EXAMPLE leaked", /AKIA[0-9A-Z]{16}/],
  ["Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig", /eyJ[A-Za-z0-9_-]+\./],
  ["Contact me at jane.doe@example.com or 415-555-0142", /[\w.]+@[\w.]+\.\w+|\b\d{3}-\d{3}-\d{4}\b/],
];

describe("LLM-OUT-001 output scrubbing", () => {
  it.each(SECRETS)("masks planted secret/PII in model output: %s", (raw, leak) => {
    const out = scrubOutput(raw);
    expect(leak.test(out), `secret survived scrubbing: ${out}`).toBe(false);
    expect(out).toMatch(/\*|REDACTED|\[redacted\]/i); // some mask token is present
  });

  it("clean model output is returned byte-for-byte (no over-masking)", () => {
    const clean = "Here is the summary of your three open tickets and their statuses.";
    expect(scrubOutput(clean)).toBe(clean);
  });
});
