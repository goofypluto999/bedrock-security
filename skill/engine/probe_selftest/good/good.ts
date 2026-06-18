// PROBE REGRESSION FIXTURE — benign code shapes that previously FALSE-fired.
// NONE of the watched checks may FAIL on this file (false-positive guard).
const token = import.meta.env.VITE_POSTHOG_TOKEN;                  // public-by-design analytics token
const pk = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY;            // publishable key is meant to be public
const env = process.env.NODE_ENV || 'development';                 // Sentry env detection, not a debug flag
console.log(`top-up of ${topupTokens} tokens for user ${userId}`); // logs a token COUNT, not a token value
const cfg = { SUPABASE_SERVICE_ROLE_KEY: 'test_service_role_key', STRIPE_SECRET_KEY: 'sk_test_placeholder' };  // test placeholders
console.error(`Webhook CRITICAL: profile patch failed after token credit for user ${userId}`);  // "token" is a word
const desc = "DESCRIPTION SUMMARY: a 2-3 sentence summary";        // "DEScription" is not the DES cipher
