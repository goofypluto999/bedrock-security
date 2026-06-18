/**
 * CLIENT-ENV-001 — No secret behind a client-exposed env prefix (CWE-200, CWE-615, OWASP A02:2021).
 * Stack: TypeScript/Node (vitest + fs). Static scan of the BUILT client bundle/dist — no server needed.
 *
 * PROVE: nothing with a client-exposed prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, PUBLIC_)
 * is a secret, and no server-only secret VALUE appears compiled into the shipped bundle. Anything in
 * dist/ is readable by anyone in the browser. Supabase: only the anon key is client-safe — service_role
 * must never reach the client.
 *
 * Wire the TODOs: point DIST at your build output and SERVER_SECRET_VALUES at real server-only values.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const DIST = "dist"; // TODO: ".next", "build", or "dist" — your bundler's client output dir.
// TODO: read these from the SERVER-side env at test time; their VALUES must not be in the bundle.
const SERVER_SECRET_VALUES = [process.env.SUPABASE_SERVICE_ROLE_KEY, process.env.STRIPE_SECRET_KEY].filter(Boolean) as string[];

function bundleFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) return bundleFiles(p);
    return /\.(js|mjs|cjs|map|html)$/.test(e) ? [p] : [];
  });
}

describe("CLIENT-ENV-001 client bundle exposure", () => {
  const files = bundleFiles(DIST);
  const blob = files.map((f) => readFileSync(f, "utf8")).join("\n");

  it("no server secret VALUE is compiled into the client bundle", () => {
    for (const v of SERVER_SECRET_VALUES) {
      expect(blob.includes(v), "a server-only secret value is present in the shipped bundle").toBe(false);
    }
  });

  it("no secret-bearing var uses a client-exposed prefix", () => {
    const bad = /(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*(KEY|SECRET|TOKEN|PASSWORD|SERVICE_ROLE|PRIVATE)/;
    expect(bad.test(blob), "a secret-named var is exposed via a client-public prefix").toBe(false);
  });

  it("the Supabase service_role key never appears client-side", () => {
    expect(/service_role/.test(blob), "service_role key leaked into the client bundle").toBe(false);
  });
});
