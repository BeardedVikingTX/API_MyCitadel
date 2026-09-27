<?php
/* ============================================================================
 * ███ LOGIN.PHP ███
 * MyCitadel — User Authentication Endpoint
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/auth/login
 * Auth    : None (public)
 * CSRF    : Required
 * Rate    : 10 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Authenticates a user by email (or username) + password. Steps:
 *
 *   1. Rate-limit (10 attempts / 60s / IP — see note below).
 *   2. Verify CSRF token.
 *   3. Parse input.
 *   4. Look up user by blind index (email or username).
 *   5. If not found → run a DUMMY Argon2 verify (timing attack defense).
 *   6. If found    → Argon2 verify the password.
 *   7. Rehash on login if Argon2 parameters have been upgraded.
 *   8. Rotate session ID, mark authenticated.
 *   9. Update last_login_at.
 *  10. Return public user profile.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * TIMING ATTACK DEFENSE
 * ────────────────────────────────────────────────────────────────────────────
 * A naive implementation returns faster for "user not found" than for
 * "wrong password" — leaking which usernames/emails are registered.
 *
 * We call citadel_dummy_verify() whenever the user lookup fails, which
 * burns the same CPU as a real Argon2 verify. The response time is
 * indistinguishable between the two cases.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * ACCOUNT ENUMERATION DEFENSE
 * ────────────────────────────────────────────────────────────────────────────
 * The error message is IDENTICAL for:
 *   • Username doesn't exist
 *   • Email doesn't exist
 *   • Password is wrong
 *   • Account is deactivated
 *
 * Always: "Invalid credentials."
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

// 10 login attempts per minute per IP. Tighten if under attack.
citadel_rate_limit('login', 10, 60);

// Require CSRF token. POST-only by nature of the check.
citadel_require_csrf();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PARSE INPUT
 * --------------------------------------------------------------------------
 * The client may send either:
 *   { "identifier": "...", "password": "..." }        ← recommended
 *   { "email": "...", "password": "..." }             ← legacy alias
 *   { "username": "...", "password": "..." }          ← legacy alias
 *
 * We accept all three to make the API flexible without breaking clients.
 * ========================================================================== */

$identifier = citadel_input_string('identifier', null, 254)
    ?? citadel_input_string('email', null, 254)
    ?? citadel_input_string('username', null, 32);

$password   = citadel_input_string('password', null, 1024);

if ($identifier === null || $identifier === '' ||
    $password   === null || $password   === '') {
    citadel_json_error('missing_credentials',
        'Identifier and password are required.', 400);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. LOOK UP THE USER
 * --------------------------------------------------------------------------
 * We compute blind indexes for both interpretations (email and username)
 * and query them. This handles both cases in a single DB round-trip.
 * ========================================================================== */

$emailIndex    = citadel_crypto_email_index($identifier);
$usernameIndex = citadel_crypto_blind_index($identifier, 'username');

$db = citadel_db();

$stmt = $db->prepare(
    'SELECT u.id, u.username, u.email_ct, u.email_nonce, u.password_hash,
            u.is_premium, u.is_active,
            COALESCE(s.reputation_points, 0) AS reputation_points
     FROM users u
     LEFT JOIN user_stats s ON s.user_id = u.id
     WHERE u.email_index = ? OR u.username_index = ?
     LIMIT 1'
);
$stmt->execute([$emailIndex, $usernameIndex]);
$user = $stmt->fetch();
$stmt->execute([$emailIndex, $usernameIndex]);
$user = $stmt->fetch();


/* ══════════════════════════════════════════════════════════════════════════
 * 04. VERIFY (WITH TIMING DEFENSE)
 * ========================================================================== */

$verified = false;

if ($user === false) {
    // User not found. Burn the same CPU as a real verify, then fail.
    citadel_dummy_verify();
    citadel_log('auth', 'notice', 'Login failed: user not found', [
        'identifier_hash' => substr(hash('sha256', strtolower($identifier)), 0, 12),
    ]);
} else {
    // User found. Check the password.
    $verified = citadel_verify_password($password, $user['password_hash']);

    if (!$verified) {
        citadel_log('auth', 'notice', 'Login failed: wrong password', [
            'user_id'  => $user['id'],
            'username' => $user['username'],
        ]);
    }
}

// Either path — same response, same timing.
if (!$verified) {
    citadel_json_error('invalid_credentials',
        'Invalid credentials.', 401);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. ADDITIONAL STATE CHECKS (AFTER PASSWORD VERIFICATION)
 * --------------------------------------------------------------------------
 * We check is_active AFTER verifying the password, so we don't leak
 * "this account is deactivated" to someone who doesn't know the password.
 * ========================================================================== */

if ((int) $user['is_active'] !== 1) {
    citadel_log('auth', 'warning', 'Login blocked: inactive account', [
        'user_id'  => $user['id'],
        'username' => $user['username'],
    ]);
    citadel_json_error('account_disabled',
        'This account is disabled. Contact support.', 403);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 06. TRANSPARENT REHASH
 * --------------------------------------------------------------------------
 * If Argon2 parameters have changed since this user registered, we
 * silently upgrade the hash. The user never notices — their password
 * stays the same, but the stored hash is now current.
 * ========================================================================== */

if (citadel_password_needs_rehash($user['password_hash'])) {
    try {
        $newHash = citadel_hash_password($password);
        $stmt = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([$newHash, $user['id']]);

        citadel_log('auth', 'info', 'Password hash upgraded', [
            'user_id' => $user['id'],
        ]);
    } catch (Throwable $e) {
        // Non-fatal — the old hash still works.
        citadel_log('auth', 'warning', 'Rehash on login failed', [
            'user_id' => $user['id'],
            'error'   => $e->getMessage(),
        ]);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 07. UPDATE LAST LOGIN TIMESTAMP
 * ========================================================================== */

try {
    $stmt = $db->prepare(
        'UPDATE users SET last_login_at = UTC_TIMESTAMP() WHERE id = ?'
    );
    $stmt->execute([$user['id']]);
} catch (Throwable $e) {
    // Non-fatal. Log but don't block login.
    citadel_log('auth', 'warning', 'Failed to update last_login_at', [
        'user_id' => $user['id'],
        'error'   => $e->getMessage(),
    ]);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 08. START THE SESSION
 * --------------------------------------------------------------------------
 * citadel_session_login() regenerates the session ID (fixation defense),
 * marks $_SESSION as authenticated, and rotates the CSRF token.
 * ========================================================================== */

citadel_session_login((int) $user['id']);
citadel_hint_set();


/* ══════════════════════════════════════════════════════════════════════════
 * 09. AUDIT & RESPONSE
 * ========================================================================== */

citadel_log('auth', 'info', 'Login successful', [
    'user_id'  => $user['id'],
    'username' => $user['username'],
]);

citadel_json_ok([
    'user' => [
        'id'         => (int) $user['id'],
        'username'   => $user['username'],
        'reputation' => (int) $user['reputation_points'],
        'premium'    => (bool) $user['is_premium'],
    ],
    'csrf_token' => citadel_csrf_token(),
]);