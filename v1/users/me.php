<?php
/* ============================================================================
 * ███ ME.PHP ███
 * MyCitadel — Current User Profile Endpoint
 * ----------------------------------------------------------------------------
 * Route   : GET /v1/users/me
 * Auth    : Required
 * CSRF    : Not required (safe method: GET)
 * Rate    : 60 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Returns the profile of the currently authenticated user. This is the
 * "who am I?" endpoint — every client (web, Android, iOS) calls it after
 * login to render the dashboard.
 *
 * Flow:
 *   1. Verify session is authenticated.
 *   2. Fetch the user row by session-stored user_id.
 *   3. Decrypt the PII columns (email) using the per-user envelope key.
 *   4. Return a profile object with public + private fields.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * RESPONSE SHAPE
 * ────────────────────────────────────────────────────────────────────────────
 *   {
 *     "status": "ok",
 *     "user": {
 *       "id":             1,
 *       "username":       "BeardedVikingTX",
 *       "email":          "viking@example.com",   ← decrypted from envelope
 *       "reputation":     0,
 *       "premium":        false,
 *       "email_verified": false,
 *       "is_active":      true,
 *       "created_at":     "2026-09-26T19:00:00+00:00",
 *       "last_login_at":  "2026-09-26T19:00:25+00:00"
 *     }
 *   }
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT WE NEVER RETURN
 * ────────────────────────────────────────────────────────────────────────────
 *   ✗ password_hash      — even hashed, it's sensitive metadata
 *   ✗ email_ct           — internal ciphertext, no client use for it
 *   ✗ email_nonce        — internal, no client use
 *   ✗ email_index        — blind index, no client use
 *   ✗ username_index     — blind index, no client use
 *   ✗ session_id         — internal
 *
 * The client gets the DECRYPTED email and nothing else from the crypto layer.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

// Rate limit generously — this is a read-only endpoint hit on every page load.
citadel_rate_limit('me', 60, 60);

// Requires auth. Returns 401 JSON if not logged in.
citadel_require_auth('json');


/* ══════════════════════════════════════════════════════════════════════════
 * 02. METHOD CHECK
 * ========================================================================== */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed',
        'This endpoint accepts GET only.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. FETCH THE USER
 * ========================================================================== */

$userId = citadel_current_user_id();
if ($userId === null) {
    // Should never happen — citadel_require_auth() already checked.
    citadel_json_error('not_authenticated', 'Session has no user.', 401);
}

$db = citadel_db();

$stmt = $db->prepare(
    'SELECT id, username, email_ct, email_nonce,
            reputation, premium, email_verified, is_active,
            created_at, updated_at, last_login_at
     FROM users
     WHERE id = ?
     LIMIT 1'
);
$stmt->execute([$userId]);
$user = $stmt->fetch();

if ($user === false) {
    // Session is valid but the user row is gone. Someone deleted the account
    // mid-session. Destroy the session and tell the client.
    citadel_log('auth', 'warning', 'Session user_id has no matching row', [
        'user_id' => $userId,
    ]);
    citadel_session_destroy();
    citadel_json_error('account_missing',
        'Your account no longer exists.', 401);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. DECRYPT THE EMAIL
 * ========================================================================== */

$email = citadel_crypto_decrypt(
    $user['email_ct'],
    $user['email_nonce'],
    (int) $user['id']
);

if ($email === null) {
    // Decryption failed — key mismatch, corruption, or tampering.
    // This is a serious condition; log it but don't leak details to the client.
    citadel_log('security', 'error', 'Email decryption failed on /me', [
        'user_id' => $user['id'],
    ]);
    // Fall back to a placeholder; the profile still returns.
    $email = null;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. RESPONSE
 * ========================================================================== */

citadel_json_ok([
    'user' => [
        'id'             => (int) $user['id'],
        'username'       => $user['username'],
        'email'          => $email,
        'reputation'     => (int) $user['reputation'],
        'premium'        => (bool) $user['premium'],
        'email_verified' => (bool) $user['email_verified'],
        'is_active'      => (bool) $user['is_active'],
        'created_at'     => gmdate('c', strtotime($user['created_at'])),
        'updated_at'     => gmdate('c', strtotime($user['updated_at'])),
        'last_login_at'  => $user['last_login_at']
            ? gmdate('c', strtotime($user['last_login_at']))
            : null,
    ],
]);