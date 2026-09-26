<?php
/* ============================================================================
 * ███ REGISTER.PHP ███
 * MyCitadel — User Registration Endpoint
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/auth/register
 * Auth    : None (public endpoint)
 * CSRF    : Required (double-submit cookie)
 * Rate    : 5 requests per hour per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Creates a new MyCitadel user account. The flow is:
 *
 *   1. Rate-limit the request (per IP).
 *   2. Verify CSRF token.
 *   3. Parse & validate JSON input.
 *   4. Check availability (username + email, via blind indexes).
 *   5. Hash the password with Argon2id.
 *   6. Encrypt the email with the user's derived key (envelope encryption).
 *   7. Insert in a transaction.
 *   8. Start a session, set the hint cookie.
 *   9. Return the public user profile.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * PRIVACY GUARANTEES
 * ────────────────────────────────────────────────────────────────────────────
 *   • Password: never stored, only Argon2id hash (one-way, unrecoverable).
 *   • Email:    stored encrypted with a per-user key derived from master.key.
 *   • Uniqueness: enforced via blind index (HMAC) — no plaintext in DB.
 *   • Audit:    IPs stored only as HMAC-SHA256 hashes, never plaintext.
 *   • Logging:  no secrets, no passwords, no plaintext PII in any log line.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * REQUEST
 * ────────────────────────────────────────────────────────────────────────────
 *   Content-Type: application/json
 *   Headers:      X-CSRF-Token: <token from /v1/auth/csrf>
 *   Body:
 *     {
 *       "username": "viking_42",
 *       "email":    "viking@example.com",
 *       "password": "correct horse battery staple"
 *     }
 *
 * ────────────────────────────────────────────────────────────────────────────
 * RESPONSES
 * ────────────────────────────────────────────────────────────────────────────
 *   201 Created   { status:"ok", user:{ id, username, reputation, premium } }
 *   400 Bad Req   { status:"error", code:"missing_fields" | "invalid_..." }
 *   403 Forbidden { status:"error", code:"csrf_invalid" }
 *   409 Conflict  { status:"error", code:"user_exists" }
 *   429 Too Many  { status:"error", code:"rate_limited" }
 *   500 Server    { status:"error", code:"hashing_failed" | "registration_failed" }
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

// Load the encryption engine. Placed here (not in bootstrap) because
// only endpoints that touch PII need it — keeps the hot path lean.
require_once CITADEL_CONFIG . '/crypto.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

// Rate limit: 5 registration attempts per hour per IP.
citadel_rate_limit('register', 5, 3600);

// Require a valid CSRF token. Rejects GET (unsafe method), forged POSTs.
citadel_require_csrf();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PARSE & VALIDATE INPUT
 * ========================================================================== */

$username = citadel_input_string('username', null, 32);
$email    = citadel_input_string('email',    null, 254);
$password = citadel_input_string('password', null, 1024);

// ── Presence ─────────────────────────────────────────────────────────────
if ($username === null || $username === '' ||
    $email    === null || $email    === '' ||
    $password === null || $password === '') {
    citadel_json_error('missing_fields',
        'Username, email, and password are required.', 400);
}

// ── Username format: 3–32 chars, letters/numbers/underscore only ─────────
if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
    citadel_json_error('invalid_username',
        'Username must be 3–32 characters using only letters, numbers, and underscores.', 400);
}

// ── Reserved usernames (impersonation prevention) ────────────────────────
$reserved = [
    'admin', 'root', 'system', 'mycitadel', 'support', 'api', 'www', 'mail',
    'noreply', 'postmaster', 'abuse', 'help', 'moderator', 'mod', 'staff',
];
if (in_array(strtolower($username), $reserved, true)) {
    citadel_json_error('reserved_username',
        'That username is reserved. Please choose another.', 400);
}

// ── Email format ─────────────────────────────────────────────────────────
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    citadel_json_error('invalid_email',
        'Please enter a valid email address.', 400);
}

// ── Password policy ──────────────────────────────────────────────────────
$pwCheck = citadel_validate_password($password);
if (!$pwCheck['valid']) {
    citadel_json_error('weak_password', $pwCheck['reason'], 400);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. AVAILABILITY CHECK
 * --------------------------------------------------------------------------
 * We compute blind indexes and query them. Two requests can race here —
 * the final arbiter is the UNIQUE constraint on the DB, which we handle
 * gracefully below.
 * ========================================================================== */

$usernameIndex = citadel_crypto_blind_index($username, 'username');
$emailIndex    = citadel_crypto_email_index($email);

$db = citadel_db();

$stmt = $db->prepare(
    'SELECT 1 FROM users
     WHERE username_index = ? OR email_index = ?
     LIMIT 1'
);
$stmt->execute([$usernameIndex, $emailIndex]);

if ($stmt->fetch() !== false) {
    // Do NOT reveal WHICH field is taken — that would be an enumeration
    // oracle. Same error for both cases.
    citadel_json_error('user_exists',
        'That username or email is already registered.', 409);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. HASH THE PASSWORD (ARGON2ID)
 * ========================================================================== */

try {
    $passwordHash = citadel_hash_password($password);
} catch (Throwable $e) {
    citadel_log('auth', 'error', 'Argon2 hashing failed during registration', [
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('hashing_failed',
        'Could not process your registration. Please try again.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. INSERT (TRANSACTION)
 * --------------------------------------------------------------------------
 * We insert with a temporary placeholder to get the auto-increment ID,
 * then encrypt the email with a key derived from THAT ID, then update.
 *
 * Why two queries? Because the per-user key derivation needs the user_id,
 * which doesn't exist until the row is inserted. The whole thing runs in
 * a transaction so no other connection ever sees the placeholder state.
 * ========================================================================== */

try {
    $db->beginTransaction();

    // ── 5a. Insert with placeholder PII ──────────────────────────────────
    $stmt = $db->prepare(
        'INSERT INTO users
            (username, username_index, email_ct, email_nonce, email_index,
             password_hash, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())'
    );
    $stmt->execute([
        $username,
        $usernameIndex,
        '',          // placeholder — filled in 5b
        '',          // placeholder — filled in 5b
        $emailIndex,
        $passwordHash,
    ]);

    $userId = (int) $db->lastInsertId();

    // ── 5b. Encrypt email with the user's derived key ────────────────────
    $encrypted = citadel_crypto_encrypt($email, $userId);

    // ── 5c. Store the ciphertext + nonce ─────────────────────────────────
    $stmt = $db->prepare(
        'UPDATE users SET email_ct = ?, email_nonce = ? WHERE id = ?'
    );
    $stmt->execute([$encrypted['ct'], $encrypted['nonce'], $userId]);

    $db->commit();

} catch (PDOException $e) {
    if ($db->inTransaction()) $db->rollBack();

    // Duplicate key (race condition between the check and the insert).
    if ($e->getCode() === '23000') {
        citadel_json_error('user_exists',
            'That username or email is already registered.', 409);
    }

    citadel_log('auth', 'error', 'Registration insert failed', [
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('registration_failed',
        'Could not create your account. Please try again.', 500);

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();

    citadel_log('auth', 'error', 'Unexpected error during registration', [
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('registration_failed',
        'Could not create your account. Please try again.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 06. AUDIT LOGGING
 * --------------------------------------------------------------------------
 * Structured event for forensics. No PII in the log line.
 * ========================================================================== */

citadel_log('auth', 'info', 'User registered', [
    'user_id'  => $userId,
    'username' => $username,  // usernames are public — safe to log
]);


/* ══════════════════════════════════════════════════════════════════════════
 * 07. SESSION START
 * --------------------------------------------------------------------------
 * Log the user in immediately. This regenerates the session ID (fixation
 * defense) and sets the public "authed" hint cookie for the UI.
 * ========================================================================== */

citadel_session_login($userId);
citadel_hint_set();


/* ══════════════════════════════════════════════════════════════════════════
 * 08. RESPONSE
 * --------------------------------------------------------------------------
 * Only public fields. Never return the email, never return the hash,
 * never return anything derived from the user's encryption keys.
 *
 * We DO return the fresh CSRF token, because citadel_session_login()
 * rotated it. Without this, the client holds a stale token and its next
 * request fails with csrf_invalid.
 * ========================================================================== */

citadel_json_ok([
    'user' => [
        'id'         => $userId,
        'username'   => $username,
        'reputation' => 0,
        'premium'    => false,
    ],
    'csrf_token' => citadel_csrf_token(),
], 201);


/* ══════════════════════════════════════════════════════════════════════════
 * ▓▓▓ END OF REGISTER.PHP ▓▓▓
 * --------------------------------------------------------------------------
 * What this file guarantees:
 *
 *   ✅ No plaintext email ever stored
 *   ✅ No password ever stored
 *   ✅ No plaintext IP ever logged
 *   ✅ No secret ever echoed to the client
 *   ✅ All encryption keyed per-user
 *   ✅ All writes atomic (transaction)
 *   ✅ All failures logged without leaking data
 *
 * If you ever add a field to the users table, ask:
 *   "Should this be encrypted? Does it need a blind index?"
 * The answer is usually yes to the first, only if searchable to the second.
 * — Bearded Viking
 * ═════════════════════════════════════════════════════════════════════════ */