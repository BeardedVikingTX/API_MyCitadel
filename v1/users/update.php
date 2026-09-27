<?php
/* ============================================================================
 * ███ UPDATE.PHP ███
 * MyCitadel — Profile Update Endpoint
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/users/update
 * Auth    : Required
 * CSRF    : Required
 * Rate    : 10 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Allows an authenticated user to update their own profile. Supports
 * partial updates — send only the fields you want to change.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * SECURITY MODEL — WHY WE REQUIRE current_password
 * ────────────────────────────────────────────────────────────────────────────
 * Two fields require the user's CURRENT password before they can be changed:
 *
 *   • email      — changing email redirects account recovery. A session
 *                  hijacker must not be able to lock out the real owner.
 *   • password   — obviously.
 *
 * Username does NOT require current_password (less sensitive), but it does
 * re-check uniqueness and update the blind index atomically.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * SUPPORTED FIELD CHANGES
 * ────────────────────────────────────────────────────────────────────────────
 *
 *   {
 *     "current_password": "...",     ← required if email or password changes
 *     "username":         "new_name" ← optional
 *     "email":            "new@x.tld"← optional
 *     "new_password":     "..."      ← optional
 *   }
 *
 * Any subset of {username, email, new_password} is acceptable, but at least
 * one must be present.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * ENCRYPTION HANDLING
 * ────────────────────────────────────────────────────────────────────────────
 * Email is stored as (email_ct, email_nonce, email_index). When a user
 * changes their email, we:
 *   1. Compute the new blind index → check uniqueness.
 *   2. Re-encrypt with the user's derived key.
 *   3. Update all three columns atomically inside a transaction.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('update', 10, 60);
citadel_require_csrf();
citadel_require_auth('json');

$method = $_SERVER['REQUEST_METHOD'] ?? 'POST';
if (!in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
    header('Allow: POST, PUT, PATCH');
    citadel_json_error('method_not_allowed',
        'This endpoint accepts POST, PUT, or PATCH.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PARSE INPUT
 * ========================================================================== */

$currentPassword = citadel_input_string('current_password', null, 1024);
$newUsername     = citadel_input_string('username',         null, 32);
$newEmail        = citadel_input_string('email',            null, 254);
$newPassword     = citadel_input_string('new_password',     null, 1024);

// At least one field must be provided.
if ($newUsername === null && $newEmail === null && $newPassword === null) {
    citadel_json_error('no_changes',
        'Provide at least one of: username, email, new_password.', 400);
}

// Empty strings count as "not provided" — avoid accidental clears.
if ($newUsername === '') $newUsername = null;
if ($newEmail    === '') $newEmail    = null;
if ($newPassword === '') $newPassword = null;


/* ══════════════════════════════════════════════════════════════════════════
 * 03. LOAD THE CURRENT USER
 * ========================================================================== */

$userId = citadel_current_user_id();
$db = citadel_db();

$stmt = $db->prepare(
    'SELECT u.id, u.username, u.username_index, u.email_ct, u.email_nonce,
            u.email_index, u.password_hash, u.is_premium, u.email_verified,
            u.is_active, u.created_at, u.last_login_at,
            COALESCE(s.reputation_points, 0) AS reputation_points
     FROM users u
     LEFT JOIN user_stats s ON s.user_id = u.id
     WHERE u.id = ?
     LIMIT 1'
);
$stmt->execute([$userId]);
$user = $stmt->fetch();

if ($user === false) {
    citadel_session_destroy();
    citadel_json_error('account_missing',
        'Your account no longer exists.', 401);
}

$user = array_merge($user, ['id' => (int) $user['id']]);


/* ══════════════════════════════════════════════════════════════════════════
 * 04. VERIFY CURRENT PASSWORD (IF REQUIRED)
 * ========================================================================== */

$requiresCurrentPassword = ($newEmail !== null || $newPassword !== null);

if ($requiresCurrentPassword) {
    if ($currentPassword === null || $currentPassword === '') {
        citadel_json_error('current_password_required',
            'Changing your email or password requires your current password.', 400);
    }

    if (!citadel_verify_password($currentPassword, $user['password_hash'])) {
        citadel_log('auth', 'notice', 'Profile update: wrong current password', [
            'user_id'  => $user['id'],
            'username' => $user['username'],
        ]);
        citadel_json_error('invalid_current_password',
            'Your current password is incorrect.', 403);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. PREPARE THE UPDATE (VALIDATE EVERYTHING BEFORE WRITING)
 * --------------------------------------------------------------------------
 * We do all validation up front so the transaction is short.
 * ========================================================================== */

$updates   = [];   // SQL column => value
$auditCtx  = [];   // What changed, for the audit log

// ── Username ─────────────────────────────────────────────────────────────
if ($newUsername !== null) {
    if ($newUsername === $user['username']) {
        // No-op — user submitted the same username.
        $newUsername = null;
    } else {
        if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $newUsername)) {
            citadel_json_error('invalid_username',
                'Username must be 3–32 characters: letters, numbers, underscores only.', 400);
        }

        $reserved = [
            'admin','root','system','mycitadel','support','api','www','mail',
            'noreply','postmaster','abuse','help','moderator','mod','staff',
        ];
        if (in_array(strtolower($newUsername), $reserved, true)) {
            citadel_json_error('reserved_username',
                'That username is reserved.', 400);
        }

        $newUsernameIndex = citadel_crypto_blind_index($newUsername, 'username');

        // Uniqueness — must not collide with another user.
        $chk = $db->prepare(
            'SELECT 1 FROM users WHERE username_index = ? AND id != ? LIMIT 1'
        );
        $chk->execute([$newUsernameIndex, $user['id']]);
        if ($chk->fetch() !== false) {
            citadel_json_error('username_taken',
                'That username is already in use.', 409);
        }

        $updates['username']       = $newUsername;
        $updates['username_index'] = $newUsernameIndex;
        $auditCtx['username']      = ['from' => $user['username'], 'to' => $newUsername];
    }
}

// ── Email ────────────────────────────────────────────────────────────────
if ($newEmail !== null) {
    if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
        citadel_json_error('invalid_email',
            'Please enter a valid email address.', 400);
    }

    // Compare plaintext to current (decrypt for comparison).
    $currentEmail = citadel_crypto_decrypt(
        $user['email_ct'], $user['email_nonce'], $user['id']
    );

    if ($currentEmail !== null && strtolower($currentEmail) === strtolower($newEmail)) {
        // No-op — same email.
        $newEmail = null;
    } else {
        $newEmailIndex = citadel_crypto_email_index($newEmail);

        // Uniqueness.
        $chk = $db->prepare(
            'SELECT 1 FROM users WHERE email_index = ? AND id != ? LIMIT 1'
        );
        $chk->execute([$newEmailIndex, $user['id']]);
        if ($chk->fetch() !== false) {
            citadel_json_error('email_taken',
                'That email is already registered.', 409);
        }

        // Encrypt with the user's derived key.
        $encrypted = citadel_crypto_encrypt($newEmail, $user['id']);

        $updates['email_ct']     = $encrypted['ct'];
        $updates['email_nonce']  = $encrypted['nonce'];
        $updates['email_index']  = $newEmailIndex;
        // Changing email resets verification — user must re-verify.
        $updates['email_verified'] = 0;

        $auditCtx['email'] = 'changed'; // never log the actual addresses
    }
}

// ── Password ─────────────────────────────────────────────────────────────
$newPasswordHash = null;
if ($newPassword !== null) {
    $pwCheck = citadel_validate_password($newPassword);
    if (!$pwCheck['valid']) {
        citadel_json_error('weak_password', $pwCheck['reason'], 400);
    }

    // Reject if the new password matches the current one.
    if (citadel_verify_password($newPassword, $user['password_hash'])) {
        citadel_json_error('password_unchanged',
            'Your new password must differ from your current one.', 400);
    }

    try {
        $newPasswordHash = citadel_hash_password($newPassword);
    } catch (Throwable $e) {
        citadel_log('auth', 'error', 'Hashing failed during profile update', [
            'user_id' => $user['id'],
            'error'   => $e->getMessage(),
        ]);
        citadel_json_error('hashing_failed',
            'Could not process your update. Please try again.', 500);
    }

    $updates['password_hash'] = $newPasswordHash;
    $auditCtx['password']     = 'changed';
}

// If everything turned out to be a no-op, tell the client.
if (empty($updates)) {
    citadel_json_error('no_changes',
        'Nothing to update.', 400);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 06. APPLY THE UPDATE (TRANSACTION)
 * ========================================================================== */

try {
    $db->beginTransaction();

    $setClauses = [];
    $params     = [];
    foreach ($updates as $col => $val) {
        $setClauses[] = "{$col} = ?";
        $params[]     = $val;
    }
    $setClauses[] = 'updated_at = UTC_TIMESTAMP()';
    $params[]     = $user['id'];

    $sql = 'UPDATE users SET ' . implode(', ', $setClauses) . ' WHERE id = ?';
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    $db->commit();

} catch (PDOException $e) {
    if ($db->inTransaction()) $db->rollBack();

    // Race condition: another request took the username/email in between
    // our check and our update. The UNIQUE constraints catch this.
    if ($e->getCode() === '23000') {
        citadel_json_error('conflict',
            'That username or email was just taken. Please try again.', 409);
    }

    citadel_log('auth', 'error', 'Profile update failed', [
        'user_id' => $user['id'],
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('update_failed',
        'Could not update your profile. Please try again.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 07. AUDIT
 * ========================================================================== */

citadel_log('auth', 'info', 'Profile updated', [
    'user_id' => $user['id'],
    'changes' => $auditCtx,
]);


/* ══════════════════════════════════════════════════════════════════════════
 * 08. RESPONSE — return the fresh profile
 * ========================================================================== */

// Reload the row so we return canonical state, not our in-memory guesses.
$stmt = $db->prepare(
    'SELECT u.id, u.username, u.email_ct, u.email_nonce,
            u.is_premium, u.email_verified, u.is_active,
            u.created_at, u.updated_at, u.last_login_at,
            COALESCE(s.reputation_points, 0) AS reputation_points
     FROM users u
     LEFT JOIN user_stats s ON s.user_id = u.id
     WHERE u.id = ?
     LIMIT 1'
);
$stmt->execute([$user['id']]);
$fresh = $stmt->fetch();

$email = citadel_crypto_decrypt(
    $fresh['email_ct'], $fresh['email_nonce'], (int) $fresh['id']
);

citadel_json_ok([
    'user' => [
        'id'             => (int) $fresh['id'],
        'username'       => $fresh['username'],
        'email'          => $email,
        'reputation'     => (int) $fresh['reputation'],
        'premium'        => (bool) $fresh['premium'],
        'email_verified' => (bool) $fresh['email_verified'],
        'is_active'      => (bool) $fresh['is_active'],
        'created_at'     => gmdate('c', strtotime($fresh['created_at'])),
        'updated_at'     => gmdate('c', strtotime($fresh['updated_at'])),
        'last_login_at'  => $fresh['last_login_at']
            ? gmdate('c', strtotime($fresh['last_login_at']))
            : null,
    ],
]);