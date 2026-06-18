// PROBE REGRESSION FIXTURE — intentionally vulnerable. NOT real code.
// CLIENT-ENV-001 must FAIL: a never-public secret behind a client-exposed prefix.
const role = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;
const sec = import.meta.env.NEXT_PUBLIC_API_SECRET;
