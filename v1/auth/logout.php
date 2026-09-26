<?php
/* ============================================================================
 * ███ LOGOUT.PHP ███
 * MyCitadel — Session Termination Endpoint
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/auth/logout
 * Auth    : Required (must be logged in)
 * CSRF    : Required
 * Rate    : 30 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Terminates the current session. This is deliberately destructive:
 *
 *   • Marks the session as de-authenticated
 *   • Destroys all server-side session data
 *   • Clears the citadel_sid cookie (HttpOnly — server-side only)
 *   • Clears the citadel_csrf cookie (JS-readable)
 *   • Clears the citadel_authed hint cookie (JS-readable)
 *   • Writes an audit log entry
 *
 * The response includes NO new CSRF token — because the session is gone.
 * The client should treat "logged out" as "start fresh."
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('logout', 30, 60);
citadel_require_csrf();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. REQUIRE AUTHENTICATION
 * --------------------------------------------------------------------------
 * Logging out without being logged in is a client bug — reject it cleanly
 * so the client can correct its state.
 * ========================================================================== */

if (!citadel_is_authenticated()) {
    citadel_json_error('not_authenticated',
        'You are not logged in.', 401);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. AUDIT (BEFORE DESTRUCTION)
 * --------------------------------------------------------------------------
 * Capture the user_id before citadel_session_destroy() wipes $_SESSION.
 * ========================================================================== */

$userId = citadel_current_user_id();

citadel_log('auth', 'info', 'Logout', [
    'user_id' => $userId,
]);


/* ══════════════════════════════════════════════════════════════════════════
 * 04. DESTROY EVERYTHING
 * --------------------------------------------------------------------------
 * citadel_session_destroy() (from session.php):
 *   • Empties $_SESSION
 *   • Sets citadel_sid cookie to expired
 *   • Calls session_destroy()
 *   • Clears citadel_csrf cookie
 *   • Clears citadel_authed hint cookie
 * ========================================================================== */

citadel_session_destroy();


/* ══════════════════════════════════════════════════════════════════════════
 * 05. RESPONSE
 * --------------------------------------------------------------------------
 * No new CSRF token — the session that would store it is gone.
 * The client's next request should call /v1/auth/csrf first.
 * ========================================================================== */

citadel_json_ok([
    'message' => 'You have been logged out.',
]);