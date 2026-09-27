<?php
/* ============================================================================
 * ███ REGISTER.PHP ███
 * MyCitadel — User Registration (with referral + full profile init)
 * ----------------------------------------------------------------------------
 * Route : POST /v1/auth/register
 * Auth  : None (public)
 * CSRF  : Required
 * Rate  : 5/hour per IP
 *
 * ATOMIC OPERATION
 *   In a single transaction, this endpoint creates:
 *     1. users row                  (auth, encrypted email, referral code)
 *     2. user_profiles row          (visibility=public, all PII empty)
 *     3. user_stats row             (all counters zero)
 *     4. registration badge award   (500 reputation points via ledger)
 *     5. referral link (if code)    (awards 500 points to the referrer)
 *
 *   If ANY step fails, the entire registration rolls back. No partial users.
 *
 * REQUEST
 *   {
 *     "username":      "viking_42",
 *     "email":         "viking@example.com",
 *     "password":      "correct horse battery staple",
 *     "referral_code": "BEARDE-A7X9"        ← optional
 *   }
 *
 * RESPONSE 201
 *   {
 *     "status": "ok",
 *     "user": {
 *       "id": 1, "username": "viking_42",
 *       "referral_code": "VIKING-A7X9",
 *       "reputation": 500, "premium": false
 *     },
 *     "csrf_token": "..."
 *   }
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/reputation.php';  // award_points()
require_once CITADEL_CONFIG . '/badges.php';      // award_badge()


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('register', 5, 3600);
citadel_require_csrf();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. INPUT
 * ========================================================================== */

$username      = citadel_input_string('username',      null, 32);
$email         = citadel_input_string('email',         null, 254);
$password      = citadel_input_string('password',      null, 1024);
$referralInput = citadel_input_string('referral_code', null, 16);

if (!$username || !$email || !$password) {
    citadel_json_error('missing_fields',
        'Username, email, and password are required.', 400);
}

if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
    citadel_json_error('invalid_username',
        'Username must be 3–32 characters: letters, numbers, underscores only.', 400);
}

$reserved = ['admin','root','system','mycitadel','support','api','www','mail',
             'noreply','postmaster','abuse','help','moderator','mod','staff'];
if (in_array(strtolower($username), $reserved, true)) {
    citadel_json_error('reserved_username',
        'That username is reserved. Please choose another.', 400);
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    citadel_json_error('invalid_email',
        'Please enter a valid email address.', 400);
}

$pwCheck = citadel_validate_password($password);
if (!$pwCheck['valid']) {
    citadel_json_error('weak_password', $pwCheck['reason'], 400);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. AVAILABILITY CHECK (username + email via blind indexes)
 * ========================================================================== */

$usernameIndex = citadel_crypto_blind_index($username, 'username');
$emailIndex    = citadel_crypto_email_index($email);

$db = db();

$existing = db_one(
    'SELECT 1 FROM users WHERE username_index = ? OR email_index = ? LIMIT 1',
    [$usernameIndex, $emailIndex]
);
if ($existing !== null) {
    // Same error for both — no enumeration oracle.
    citadel_json_error('user_exists',
        'That username or email is already registered.', 409);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. HASH PASSWORD
 * ========================================================================== */

try {
    $passwordHash = citadel_hash_password($password);
} catch (Throwable $e) {
    citadel_log('auth', 'error', 'Argon2 hashing failed', ['error' => $e->getMessage()]);
    citadel_json_error('hashing_failed', 'Could not process registration.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. GENERATE REFERRAL CODE (unique)
 * ========================================================================== */

function citadel_generate_referral_code(string $username): string
{
    $prefix = strtoupper(substr(preg_replace('/[^a-zA-Z0-9]/', '', $username), 0, 6));
    $suffix = strtoupper(bin2hex(random_bytes(2)));
    return "{$prefix}-{$suffix}";
}

$referralCode  = null;
$attempts      = 0;
do {
    $candidate = citadel_generate_referral_code($username);
    $taken = db_scalar('SELECT 1 FROM users WHERE referral_code = ? LIMIT 1', [$candidate]);
    if ($taken === null) {
        $referralCode = $candidate;
        break;
    }
    $attempts++;
} while ($attempts < 5);

if ($referralCode === null) {
    citadel_log('auth', 'error', 'Referral code generation exhausted');
    citadel_json_error('registration_failed', 'Could not create your account.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 06. RESOLVE REFERRER (if any)
 * --------------------------------------------------------------------------
 * We do NOT award the referral points yet — we need the new user's ID first.
 * ========================================================================== */

$referrerId = null;
$referralCodeUsed = null;

if ($referralInput !== null && $referralInput !== '') {
    $normalized = strtoupper(trim($referralInput));
    $referrer = db_one(
        'SELECT id FROM users WHERE referral_code = ? AND is_active = 1 AND is_banned = 0 LIMIT 1',
        [$normalized]
    );
    if ($referrer !== null) {
        $referrerId = (int) $referrer['id'];
        $referralCodeUsed = $normalized;
    }
    // Invalid referral codes are silently ignored — no error, no enumeration.
}


/* ══════════════════════════════════════════════════════════════════════════
 * 07. ATOMIC REGISTRATION
 * ========================================================================== */

try {
    $db->beginTransaction();

    // ── 7a. users row (placeholder email, filled in 7b) ──────────────────
    db_query(
        'INSERT INTO users
            (username, username_index,
             email_ct, email_nonce, email_index,
             password_hash, password_changed_at,
             referral_code, referred_by,
             created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
        [$username, $usernameIndex,
         '', '', $emailIndex,
         $passwordHash,
         $referralCode, $referrerId]
    );

    $userId = db_last_id();

    // ── 7b. encrypt email with derived key ───────────────────────────────
    $encrypted = citadel_crypto_encrypt($email, $userId);

    db_query(
        'UPDATE users SET email_ct = ?, email_nonce = ? WHERE id = ?',
        [$encrypted['ct'], $encrypted['nonce'], $userId]
    );

    // ── 7c. user_profiles row (visibility = public by default) ───────────
    db_query(
        'INSERT INTO user_profiles (user_id, visibility, created_at, updated_at)
         VALUES (?, "public", UTC_TIMESTAMP(), UTC_TIMESTAMP())',
        [$userId]
    );

    // ── 7d. user_stats row (all counters zero) ───────────────────────────
    db_query(
        'INSERT INTO user_stats (user_id, updated_at)
         VALUES (?, UTC_TIMESTAMP())',
        [$userId]
    );

    // ── 7e. award registration badge (500 points via ledger) ─────────────
    // award_badge() opens its own transaction only if none is active.
    // We're inside one, so it participates cleanly.
    award_badge($userId, 'registration', 'welcome');

    // ── 7f. referral reward (if valid code was supplied) ─────────────────
    if ($referrerId !== null && $referralCodeUsed !== null) {
        // Referral ledger row
        db_query(
            'INSERT INTO referrals
                (referrer_id, referred_user_id, code_used,
                 points_awarded, rewarded_at, created_at)
             VALUES (?, ?, ?, 500, UTC_TIMESTAMP(), UTC_TIMESTAMP())',
            [$referrerId, $userId, $referralCodeUsed]
        );

        // Award 500 points to the referrer via the ledger
        award_points(
            $referrerId,
            'referral',
            500,
            'user',
            $userId,
            "Referral: {$username} joined"
        );

        // Bump the referrer's counter
        bump_stat($referrerId, 'referral_count', 1);
    }

    $db->commit();

} catch (PDOException $e) {
    if ($db->inTransaction()) $db->rollBack();

    // Duplicate key = race condition on username/email
    if ($e->getCode() === '23000') {
        citadel_json_error('user_exists',
            'That username or email is already registered.', 409);
    }

    citadel_log('auth', 'error', 'Registration failed', ['error' => $e->getMessage()]);
    citadel_json_error('registration_failed',
        'Could not create your account. Please try again.', 500);

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('auth', 'error', 'Unexpected registration error', ['error' => $e->getMessage()]);
    citadel_json_error('registration_failed',
        'Could not create your account. Please try again.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 08. AUDIT
 * ========================================================================== */

citadel_log('auth', 'info', 'User registered', [
    'user_id'      => $userId,
    'username'     => $username,
    'referred_by'  => $referrerId,
]);


/* ══════════════════════════════════════════════════════════════════════════
 * 09. SESSION + RESPONSE
 * ========================================================================== */

citadel_session_login($userId);
citadel_hint_set();

citadel_json_ok([
    'user' => [
        'id'            => $userId,
        'username'      => $username,
        'referral_code' => $referralCode,
        'reputation'    => 500, // registration badge bonus
        'premium'       => false,
    ],
    'csrf_token' => citadel_csrf_token(),
], 201);