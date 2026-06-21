/**
 * CACHE-TENANT-001 — Cache keys are tenant-scoped (no cross-tenant cache bleed) (OWASP API1:2023, CWE-524).
 * Stack: TypeScript / Node (vitest + supertest). Works for Redis, CDN, in-memory, Next.js unstable_cache.
 *
 * PROVE: tenant A's cached response is NOT served to tenant B on the same path. Also prove that a
 * repeat request from tenant A still hits the cache (i.e. the fix did not disable caching entirely).
 *
 * Wire the TODOs: the app handler, two tenant tokens, the cacheable resource path, and a way to
 * distinguish the cached body belonging to each tenant.
 */
import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// TODO: import or construct your HTTP app/handler.
// import { app } from "../../src/app";
const app: any = null; // TODO

let tokenA = "";
let tokenB = "";

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

// TODO: a route that returns per-tenant data AND is expected to be cached (CDN / server cache).
// Must be a GET route with the same URL for both tenants — the cache key must differentiate them.
const CACHEABLE_PATH = "/api/me/profile"; // TODO

beforeAll(async () => {
  // TODO: sign in two distinct tenants and capture their tokens.
  // tokenA = await login("tenant-a@example.com");
  // tokenB = await login("tenant-b@example.com");
});

describe("CACHE-TENANT-001 no cross-tenant cache bleed", () => {
  it("tenant A primes the cache, tenant B receives their OWN data (not A's cached body)", async () => {
    // Step 1: tenant A fetches the resource — this primes the cache.
    const respA1 = await request(app).get(CACHEABLE_PATH).set(bearer(tokenA));
    expect(respA1.status).toBe(200);
    const bodyA = extractTenantIdentity(respA1);

    // Step 2: tenant B fetches the SAME path immediately after.
    const respB = await request(app).get(CACHEABLE_PATH).set(bearer(tokenB));
    expect(respB.status).toBe(200);
    const bodyB = extractTenantIdentity(respB);

    // B must receive their own identity, not A's cached response.
    expect(bodyB).not.toEqual(bodyA);
    expect(bodyB).toBeTruthy();
    expect(bodyA).toBeTruthy();
  });

  it("no cross-tenant data appears anywhere in tenant B's response body", async () => {
    // Prime with A.
    const respA = await request(app).get(CACHEABLE_PATH).set(bearer(tokenA));
    expect(respA.status).toBe(200);

    // Assert B's full response body contains nothing from A's payload.
    const respB = await request(app).get(CACHEABLE_PATH).set(bearer(tokenB));
    expect(respB.status).toBe(200);

    const aIdentifier = extractTenantIdentity(respA);
    // A's tenant identifier must be absent from B's entire response.
    expect(JSON.stringify(respB.body)).not.toContain(aIdentifier);
  });

  it("tenant A's repeat request still benefits from the cache (no over-correction: caching not disabled)", async () => {
    // First request — primes cache.
    const resp1 = await request(app).get(CACHEABLE_PATH).set(bearer(tokenA));
    expect(resp1.status).toBe(200);

    // Second request from the SAME tenant — should be a cache hit.
    const resp2 = await request(app).get(CACHEABLE_PATH).set(bearer(tokenA));
    expect(resp2.status).toBe(200);

    // Cache hit signal: either an explicit header or a faster / identical response.
    // TODO: choose the assertion that fits your cache layer:
    //   Option A (CDN/Vercel): expect(resp2.headers["x-vercel-cache"]).toBe("HIT");
    //   Option B (explicit header): expect(resp2.headers["x-cache"]).toMatch(/hit/i);
    //   Option C (body identity as proxy): expect(resp2.body).toEqual(resp1.body);
    expect(resp2.body).toEqual(resp1.body); // fallback: same-tenant same body
  });

  it("unauthenticated request cannot prime or read the per-tenant cache", async () => {
    // Ensure an unauthed request to the cacheable path is blocked, not served cached tenant data.
    const resp = await request(app).get(CACHEABLE_PATH);
    expect([401, 403, 302, 307]).toContain(resp.status);
    // Must not contain any tenant body.
    expect(resp.body?.id ?? resp.body?.email ?? null).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TODO: replace with a selector that extracts a stable, unique tenant identity
// from the response — e.g. the tenant's user id, email, or org slug.
// ---------------------------------------------------------------------------
function extractTenantIdentity(resp: request.Response): string {
  // e.g. return resp.body?.id ?? resp.body?.email ?? "";
  return (resp.body as { id?: string; email?: string })?.id ??
         (resp.body as { email?: string })?.email ??
         "";
}
