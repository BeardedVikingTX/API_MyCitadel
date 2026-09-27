<?php
/* ============================================================================
 * ███ PASSWORD_RESET_CONSUME.PHP ███
 * MyCitadel — Password Reset: Step 3 of 3 (Set New Password)
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/verify/password_reset_consume
 * Auth    : Session-based (via $_SESSION['_citadel']['pwreset'])
 * CSRF    : Required
 * Rate    : 20 per hour per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 *  1. Verifies the session has a live pwreset authorization (set by step 2).
 *  2. Validates the new password against policy.
 *  3. Ensures the new password is different from the old one.
 *  4. In a single transaction:
 *        - Updates password_hash
 *        - Bumps password_changed_at (invalidates ALL other sessions)
 *        - Clears account lockouts (if table exists)
 *  5. Rotates the current session ID (session fixation defense).
 *  6. Marks the current session as authenticated for the new credential.
 *  7. Sends a confirmation email.
 *  8. Clears the pwreset authorization flag.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY NO TOKEN PARAMETER
 * ────────────────────────────────────────────────────────────────────────────
 * By the time this endpoint runs, the URL token has already been consumed
 * by password_reset_exchange.php. This endpoint authorizes by session, not
 * by URL. That means:
 *   • An attacker who finds the leaked URL later cannot reach this endpoint.
 *   • An attacker who forges a form POST without a valid session fails.
 *   • The same browser session must have completed step 2 first.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHY ALL OTHER SESSIONS DIE
 * ────────────────────────────────────────────────────────────────────────────
 * We bump users.password_changed_at. The session.php check (added in the
 * patch) compares that timestamp against each session's created_at. Any
 * session that existed before the password change is now invalid.
 *
 * If an attacker had a stolen session, this reset kicks them out — even if
 * they were logged in on another device.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/mailer.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

citadel_rate_limit('pwreset_consume', 20, 3600);
citadel_require_csrf();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 02. VERIFY SESSION AUTHORIZATION
 * --------------------------------------------------------------------------
 * We only proceed if this exact session completed step 2 within the last
 * 15 minutes. This is the guard that makes the whole flow attack-resistant.
 * ========================================================================== */

$auth = $_SESSION['_citadel']['pwreset'] ?? null;

if (!is_array($auth) || !isset($auth['user_id'], $auth['expires'])) {
    citadel_json_error('no_authorization',
        'Your reset session has expired. Please request a new reset link.', 403);
}

if (time() > (int) $auth['expires']) {
    unset($_SESSION['_citadel']['pwreset']);
    citadel_json_error('authorization_expired',
        'Your reset session has expired. Please request a new reset link.', 403);
}

$userId = (int) $auth['user_id'];


/* ══════════════════════════════════════════════════════════════════════════
 * 03. VALIDATE NEW PASSWORD
 * ========================================================================== */

$password = citadel_input_string('password', null, 1024);

if ($password === null || $password === '') {
    citadel_json_error('missing_password', 'A new password is required.', 400);
}

$pwCheck = citadel_validate_password($password);
if (!$pwCheck['valid']) {
    citadel_json_error('weak_password', $pwCheck['reason'], 400);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. APPLY THE RESET (ATOMIC)
 * ========================================================================== */

$db = db();
$db->beginTransaction();

try {
    // ── 4a. Load the user ───────────────────────────────────────────────
    $user = db_one(
        'SELECT id, username, email_ct, email_nonce, password_hash
           FROM users
          WHERE id = ?
          LIMIT 1',
        [$userId]
    );

    if ($user === null) {
        $db->rollBack();
        unset($_SESSION['_citadel']['pwreset']);
        citadel_json_error('invalid_session', 'Reset session is invalid.', 403);
    }

    // ── 4b. Reject if the new password matches the old one ──────────────
    if (citadel_verify_password($password, $user['password_hash'])) {
        $db->rollBack();
        citadel_json_error('password_unchanged',
            'Your new password must differ from your previous one.', 400);
    }

    // ── 4c. Hash the new password ───────────────────────────────────────
    $newHash = citadel_hash_password($password);

    // ── 4d. Update password + bump password_changed_at ──────────────────
    // Bumping this column is what invalidates all other sessions.
    db_query(
        "UPDATE users
            SET password_hash = ?,
                password_changed_at = UTC_TIMESTAMP(),
                updated_at = UTC_TIMESTAMP()
          WHERE id = ?",
        [$newHash, $userId]
    );

    // ── 4e. Clear account lockouts (if the table exists) ────────────────
    try {
        db_query(
            "UPDATE account_lockouts
                SET cleared_at = UTC_TIMESTAMP()
              WHERE user_id = ? AND cleared_at IS NULL",
            [$userId]
        );
    } catch (Throwable $e) {
        // account_lockouts may not exist yet — that's expected for now.
    }

    $db->commit();

    // Clear the reset authorization — its job is done.
    unset($_SESSION['_citadel']['pwreset']);

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('auth', 'error', 'Password reset consume failed', [
        'user_id' => $userId,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('internal_error',
        'Could not reset your password. Please try again.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. REFRESH THIS SESSION FOR THE NEW CREDENTIAL
 * --------------------------------------------------------------------------
 * The password changed. Our current session would be invalidated by the
 * password_changed_at check on the next request. So we:
 *   • Regenerate the session ID (fixation defense)
 *   • Reset the session's created_at to now (post-password-change)
 *   • Mark it authenticated for the user
 *   • Refresh the CSRF token (session ID changed)
 * ========================================================================== */

session_regenerate_id(true);

$_SESSION['_citadel']['user_id']       = $userId;
$_SESSION['_citadel']['authenticated'] = true;
$_SESSION['_citadel']['created_at']    = time();
$_SESSION['_citadel']['last_seen_at']  = time();
$_SESSION['_citadel']['regenerated']   = time();
$_SESSION['_citadel']['pw_check_at']   = time();

citadel_hint_set();
citadel_csrf_rotate();


/* ══════════════════════════════════════════════════════════════════════════
 * 06. CONFIRMATION EMAIL
 * --------------------------------------------------------------------------
 * The victim needs to know if a change happened that they didn't make.
 * This is the "detection" layer — even if we can't prevent a compromise,
 * we can inform the user the moment it happens.
 * ========================================================================== */

$email = citadel_crypto_decrypt($user['email_ct'], $user['email_nonce'], $userId);

if ($email !== null) {
    $when     = gmdate('Y-m-d H:i:s') . ' UTC';
    $username = htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8');

    $subject = 'Your MyCitadel password was changed';

    $htmlBody = <<<HTML
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Inter,Arial,sans-serif;background:#05070a;color:#e0e6ed;padding:32px;margin:0;">
  <div style="max-width:560px;margin:0 auto;background:#10151d;border:1px solid rgba(0,229,255,0.22);border-radius:14px;padding:32px;">
    <h1 style="font-family:'Cinzel',Georgia,serif;color:#7df9ff;letter-spacing:0.08em;text-transform:uppercase;margin:0 0 16px;">MyCitadel</h1>

    <p>Hello <strong style="color:#e0e6ed;">{$username}</strong>,</p>

    <p>Your MyCitadel password was successfully changed on
       <strong style="color:#e0e6ed;">{$when}</strong>.</p>

    <p><strong>All other sessions have been signed out</strong> as a
       security measure.</p>

    <p style="color:#ef4444;">
      <strong>If this wasn't you</strong>, your account may be compromised.
      Contact <a href="mailto:security@mycitadel.lol" style="color:#00e5ff;">security@mycitadel.lol</a>
      immediately.
    </p>

    <hr style="border:none;border-top:1px solid rgba(0,229,255,0.15);margin:32px 0;">
    <p style="color:#475569;font-size:12px;">
      This is an automated security notification. Please do not reply.
    </p>
  </div>
</body></html>
HTML;

    citadel_send_email($email, $subject, $htmlBody);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 07. RESPONSE
 * ========================================================================== */

citadel_log('auth', 'info', 'Password reset completed', [
    'user_id' => $userId,
]);

citadel_json_ok([
    'message'    => 'Password reset successful. You are now logged in.',
    'csrf_token' => citadel_csrf_token(),  // rotated — client must adopt
]);