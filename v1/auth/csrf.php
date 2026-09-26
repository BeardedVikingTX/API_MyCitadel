<?php
/* ============================================================================
 * ███ CSRF.PHP ███
 * MyCitadel — CSRF Token Minting Endpoint
 * ----------------------------------------------------------------------------
 * Route   : GET /v1/auth/csrf
 * Auth    : None (public)
 * CSRF    : N/A (this endpoint is what CREATES the token)
 * Rate    : Not rate-limited (cheap, idempotent, no state change)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Mints (or refreshes) a CSRF token and:
 *   • Stores it in the server-side session
 *   • Sets the `citadel_csrf` cookie (JS-readable) with the same value
 *   • Returns the token in the JSON response
 *
 * The client (browser JS, mobile app) is expected to:
 *   • Read the token from the JSON response OR from the cookie
 *   • Send it back in the `X-CSRF-Token` header on every unsafe request
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY THIS IS SAFE
 * ────────────────────────────────────────────────────────────────────────────
 * Double-submit cookie pattern. An attacker on evil.com:
 *   ✗ Cannot READ the cookie (same-origin policy)
 *   ✗ Cannot SET custom headers cross-origin (CORS blocks it)
 *
 * Even if they somehow trick a user's browser into submitting a form to
 * our API, the request arrives without the X-CSRF-Token header — and
 * without it, register/login/logout all reject the request.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY A FRESH TOKEN IS MINTED ON EVERY CALL
 * ────────────────────────────────────────────────────────────────────────────
 * Each call to /csrf rotates the token. This means:
 *   • Tokens are short-lived by convention (client refreshes as needed)
 *   • A leaked token from an old page can't be reused
 *   • Session fixation on the CSRF side is mitigated automatically
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. METHOD CHECK
 * --------------------------------------------------------------------------
 * Only GET and POST are allowed. Anything else returns 405.
 * ========================================================================== */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($method, ['GET', 'POST'], true)) {
    header('Allow: GET, POST');
    citadel_json_error('method_not_allowed',
        'This endpoint accepts GET or POST only.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 02. MINT A FRESH TOKEN
 * --------------------------------------------------------------------------
 * citadel_csrf_rotate() (defined in session.php) generates a new
 * cryptographically random 32-byte token, stores it in $_SESSION, and
 * syncs it to the citadel_csrf cookie.
 * ========================================================================== */

if (!function_exists('citadel_csrf_rotate')) {
    citadel_log('security', 'error', 'CSRF module not loaded', []);
    citadel_json_error('service_unavailable',
        'CSRF subsystem is unavailable.', 503);
}

$token = citadel_csrf_rotate();


/* ══════════════════════════════════════════════════════════════════════════
 * 03. RESPONSE
 * --------------------------------------------------------------------------
 * We return the token in the JSON body for clients (Android app) that
 * don't persist cookies. Browser clients should ideally use the cookie
 * — but either works because the server checks the session value.
 *
 * The response includes the token's TTL so clients know when to refresh.
 * ========================================================================== */

citadel_json_ok([
    'token'      => $token,
    'expires_in' => 3600, // seconds — matches the cookie's Max-Age
]);