<?php
/* ============================================================================
 * ███ LOGIN.PHP ███
 * MyCitadel — User Authentication (with lockout protection)
 * ----------------------------------------------------------------------------
 * Route : POST /v1/auth/login
 * Auth  : None (public)
 * CSRF  : Required
 * Rate  : 10/minute per IP + progressive delay + per-account lockout
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE FULL DEFENSE STACK
 * ────────────────────────────────────────────────────────────────────────────
 *   1. Per-IP rate limit (10/min)          — src/bootstrap.php
 *   2. CSRF token validation               — session.php
 *   3. Progressive delay (per identifier)  — this file
 *   4. Timing defense (dummy verify)       — argon2.php
 *   5. Account lockout (10 fails → 15 min) — this file
 *   6. Alert email (5 fails → notify)      — lockout.php
 *   7. Generic responses (no enumeration)  — this file
 *
 * ────────────────────────────────────────────────────────────────────────────
 * RESPONSE CONTRACT
 * ────────────────────────────────────────────────────────────────────────────
 *   Success : 200 { status:ok, user:{...}, csrf_token:"..." }
 *   Failure : 401 { status:error, code:"invalid_credentials",
 *                   message:"Invalid credentials." }
 *
 *   THE FAILURE RESPONSE IS IDENTICAL FOR:
 *     • Username/email not found
 *     • Wrong password
 *     • Account locked out
 *     • Account inactive
 *     • Account banned
 *   That's the enumeration defense. Never break it.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/lockout.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('login', 10, 60);
citadel_require_csrf();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PARSE INPUT
 * ========================================================================== */

$identifier = citadel_input_string('identifier', null, 254)
    ?? citadel_input_string('email', null, 254)
    ?? citadel_input_string('username', null, 32);

$password = citadel_input_string('password', null, 1024);

if ($identifier === null || $identifier === '' ||
    $password   === null || $password   === '') {
    citadel_json_error('missing_credentials',
        'Identifier and password are required.', 400);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. LOCKOUT CHECK + PROGRESSIVE DELAY
 * --------------------------------------------------------------------------
 * We compute the identifier hash and check the failure count BEFORE
 * looking up the user. This ensures the delay applies uniformly whether
 * or not the account exists.
 * ========================================================================== */

$identifierHash = citadel_lockout_identifier_hash($identifier);
$recentFails    = citadel_lockout_count_recent_failures($identifierHash);

// Apply progressive delay based on fail count.
citadel_lockout_apply_delay($recentFails);


/* ══════════════════════════════════════════════════════════════════════════
 * 04. LOOK UP THE USER
 * ========================================================================== */

$emailIndex    = citadel_crypto_email_index($identifier);
$usernameIndex = citadel_crypto_blind_index($identifier, 'username');

$db = citadel_db();

$stmt = $db->prepare(
    'SELECT u.id, u.username, u.email_ct, u.email_nonce, u.password_hash,
            u.is_premium, u.is_active, u.is_banned
       FROM users u
      WHERE u.email_index = ? OR u.username_index = ?
      LIMIT 1'
);
$stmt->execute([$emailIndex, $usernameIndex]);
$user = $stmt->fetch();


/* ══════════════════════════════════════════════════════════════════════════
 * 05. IF USER EXISTS — CHECK FOR ACTIVE LOCKOUT
 * --------------------------------------------------------------------------
 * A locked account must not be allowed to authenticate, even with the
 * correct password. Otherwise an attacker who has already guessed the
 * password could still get in despite triggering the lockout.
 * ========================================================================== */

$activeLockout = null;
if ($user !== false) {
    $activeLockout = citadel_lockout_get_active((int) $user['id']);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 06. VERIFY PASSWORD (TIMING-EQUALIZED)
 * --------------------------------------------------------------------------
 * Two paths:
 *   • User exists and not locked → verify against the real hash
 *   • User doesn't exist OR is locked → run dummy verify (same CPU)
 *
 * Either way, the response is identical.
 * ========================================================================== */

$verified = false;

if ($user === false) {
    citadel_dummy_verify();
    citadel_lockout_record_attempt($identifierHash, null, false, 'no_user');

} elseif ($activeLockout !== null) {
    citadel_dummy_verify();
    citadel_lockout_record_attempt(
        $identifierHash,
        (int) $user['id'],
        false,
        'locked'
    );

} else {
    $verified = citadel_verify_password($password, $user['password_hash']);

    if (!$verified) {
        citadel_lockout_record_attempt(
            $identifierHash,
            (int) $user['id'],
            false,
            'wrong_password'
        );
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 07. HANDLE FAILURE
 * --------------------------------------------------------------------------
 * At this point we know:
 *   $verified === false
 *   Either user doesn't exist, or is locked, or password is wrong
 *
 * We now check thresholds and trigger alert/lockout as needed.
 * The RESPONSE IS ALWAYS THE SAME.
 * ========================================================================== */

if (!$verified) {

    // Only trigger alert/lockout for real, unlocked, active users.
    // Otherwise we'd waste computation on random identifier spam.
    if ($user !== false
        && $activeLockout === null
        && (int) $user['is_active'] === 1
        && (int) $user['is_banned'] === 0
    ) {
        $userId = (int) $user['id'];

        // Recount AFTER the failure was recorded.
        $failCount = citadel_lockout_count_recent_failures($identifierHash);

        // ── Threshold 5: alert the account owner ───────────────────────
        if ($failCount >= LOCKOUT_ALERT_THRESHOLD
            && $failCount < LOCKOUT_TRIGGER_THRESHOLD) {
            try {
                citadel_lockout_send_alert($userId, $failCount);
            } catch (Throwable $e) {
                citadel_log('security', 'error', 'Alert send failed', [
                    'user_id' => $userId,
                    'error'   => $e->getMessage(),
                ]);
            }
        }

        // ── Threshold 10: create soft lockout ──────────────────────────
        if ($failCount >= LOCKOUT_TRIGGER_THRESHOLD) {
            try {
                citadel_lockout_create($userId, 'brute_force');
                citadel_log('security', 'warning', 'Account locked out', [
                    'user_id'    => $userId,
                    'fail_count' => $failCount,
                ]);
            } catch (Throwable $e) {
                citadel_log('security', 'error', 'Lockout creation failed', [
                    'user_id' => $userId,
                    'error'   => $e->getMessage(),
                ]);
            }
        }
    }

    // Generic failure response — SAME regardless of cause.
    citadel_json_error('invalid_credentials',
        'Invalid credentials.', 401);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 08. SUCCESS PATH
 * ========================================================================== */

// Reject inactive/banned accounts (checked AFTER password verification
// so we don't leak account state to someone who doesn't know the password).
if ((int) $user['is_active'] !== 1) {
    citadel_log('auth', 'warning', 'Login blocked: inactive account', [
        'user_id' => (int) $user['id'],
    ]);
    citadel_json_error('invalid_credentials', 'Invalid credentials.', 401);
}

if ((int) $user['is_banned'] === 1) {
    citadel_log('auth', 'warning', 'Login blocked: banned account', [
        'user_id' => (int) $user['id'],
    ]);
    citadel_json_error('invalid_credentials', 'Invalid credentials.', 401);
}

// Record the successful attempt + clear prior failures for this identifier.
citadel_lockout_record_attempt($identifierHash, (int) $user['id'], true);
citadel_lockout_clear_prior_failures($identifierHash);

// Clear any expired lockout records for housekeeping.
citadel_lockout_clear((int) $user['id'], 'expired');


/* ══════════════════════════════════════════════════════════════════════════
 * 09. TRANSPARENT REHASH
 * ========================================================================== */

if (citadel_password_needs_rehash($user['password_hash'])) {
    try {
        $newHash = citadel_hash_password($password);
        $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
           ->execute([$newHash, (int) $user['id']]);
        citadel_log('auth', 'info', 'Password hash upgraded', [
            'user_id' => (int) $user['id'],
        ]);
    } catch (Throwable $e) {
        citadel_log('auth', 'warning', 'Rehash on login failed', [
            'user_id' => (int) $user['id'],
            'error'   => $e->getMessage(),
        ]);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 10. UPDATE LOGIN METADATA
 * ========================================================================== */

try {
    $db->prepare(
        'UPDATE users SET last_login_at = UTC_TIMESTAMP() WHERE id = ?'
    )->execute([(int) $user['id']]);
} catch (Throwable $e) {
    citadel_log('auth', 'warning', 'Failed to update last_login_at', [
        'user_id' => (int) $user['id'],
        'error'   => $e->getMessage(),
    ]);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 11. START SESSION + RESPOND
 * ========================================================================== */

citadel_session_login((int) $user['id']);
citadel_hint_set();

citadel_log('auth', 'info', 'Login successful', [
    'user_id'  => (int) $user['id'],
    'username' => $user['username'],
]);

citadel_json_ok([
    'user' => [
        'id'         => (int) $user['id'],
        'username'   => $user['username'],
        'reputation' => 0,  // refreshed by /me if needed
        'premium'    => (bool) $user['is_premium'],
    ],
    'csrf_token' => citadel_csrf_token(),
]);