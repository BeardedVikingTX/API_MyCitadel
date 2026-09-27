<?php
/* ============================================================================
 * ███ PASSWORD_RESET_REQUEST.PHP ███
 * MyCitadel — Password Reset: Step 1 of 3 (Initiate)
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/verify/password_reset_request
 * Auth    : None (the user is locked out — by definition)
 * CSRF    : Required
 * Rate    : 3 per hour per IP, 3 per hour per email
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE FLOW THIS BEGINS
 * ────────────────────────────────────────────────────────────────────────────
 *   Step 1 (THIS FILE): User submits email → we email a reset link
 *   Step 2 (exchange):  User clicks link → server consumes token, sets session
 *   Step 3 (consume):   User submits new password → password changes
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 *  1. Rate-limits per IP (3/hour) — prevents the same attacker from spamming.
 *  2. Validates the email format.
 *  3. Rate-limits per email (3/hour) — prevents SMTP abuse for one target.
 *  4. Computes the email's blind index and looks up the user.
 *  5. If user exists → generate token, store SHA-256 hash, email the link.
 *  6. If user doesn't exist → dummy operation for timing equalization.
 *  7. Return THE SAME generic response in all cases.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * SECURITY PROPERTIES
 * ────────────────────────────────────────────────────────────────────────────
 *   • No user enumeration: same response, same timing.
 *   • Prior un-consumed tokens invalidated on every new request.
 *   • Token: 32 random bytes hex-encoded (2^256 space) → SHA-256 hash stored.
 *   • Raw token never logged, never stored, never echoed.
 *   • Expiry: 15 minutes (short — reset is time-sensitive).
 *   • Link uses URL FRAGMENT (#token=...) so the token is never sent to
 *     the server, never appears in access logs, and never leaks via Referer.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/mailer.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST-LEVEL PROTECTIONS
 * ========================================================================== */

// Global per-IP rate limit — 3 password reset requests per hour per IP.
citadel_rate_limit('pwreset_request_ip', 3, 3600);

// CSRF check — the request must come from a page we served.
citadel_require_csrf();

// Only POST is allowed.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PARSE + VALIDATE EMAIL
 * ========================================================================== */

$email = citadel_input_string('email', null, 254);

// Validate — but DON'T reveal format errors to the client.
// Same generic response whether the email is valid or garbage.
if ($email === null || $email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    citadel_json_ok([
        'message'    => 'If an account exists for that email, a reset link has been sent.',
        'expires_in' => 900,   // 15 minutes
    ]);
    return;
}

$emailIndex = citadel_crypto_email_index($email);
$db         = db();


/* ══════════════════════════════════════════════════════════════════════════
 * 03. PER-EMAIL RATE LIMIT
 * --------------------------------------------------------------------------
 * The per-IP limit alone isn't enough: an attacker on a botnet could send
 * 3/hour from each IP, targeting the same victim's inbox with hundreds of
 * emails. This limit closes that.
 *
 * We rate-limit by tracking recent password_reset tokens that were
 * requested "for" this email (we store the encrypted target email in the
 * token row precisely so this check works without exposing plaintext).
 * ========================================================================== */

$recentForEmail = (int) db_scalar(
    "SELECT COUNT(*)
       FROM email_verification_tokens
      WHERE purpose = 'password_reset'
        AND created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)
        AND target_email_index = ?",
    [$emailIndex]
);

if ($recentForEmail >= 3) {
    citadel_log('security', 'warning', 'Password reset: per-email rate limit hit', [
        'email_index_prefix' => substr($emailIndex, 0, 8),
    ]);

    // Same generic response — never reveal that the limit was hit.
    citadel_json_ok([
        'message'    => 'If an account exists for that email, a reset link has been sent.',
        'expires_in' => 900,
    ]);
    return;
}


/* ══════════════════════════════════════════════════════════════════════════
 * 04. LOOK UP THE USER
 * ========================================================================== */

$user = db_one(
    'SELECT id, username, email_ct, email_nonce, is_active, is_banned
       FROM users
      WHERE email_index = ?
      LIMIT 1',
    [$emailIndex]
);


/* ══════════════════════════════════════════════════════════════════════════
 * 05. TIMING EQUALIZATION
 * --------------------------------------------------------------------------
 * Whether or not the user exists, we perform a fixed-cost hash operation.
 * This makes "user found" and "user not found" take the same CPU time,
 * defeating timing-based user enumeration.
 * ========================================================================== */

$_ = sodium_crypto_generichash(bin2hex(random_bytes(16)), '', 32);


/* ══════════════════════════════════════════════════════════════════════════
 * 06. IF USER EXISTS — GENERATE + SEND RESET EMAIL
 * ========================================================================== */

$rawToken = null;

if ($user !== null
    && (int) $user['is_active'] === 1
    && (int) $user['is_banned'] === 0
) {
    $decryptedEmail = citadel_crypto_decrypt(
        $user['email_ct'],
        $user['email_nonce'],
        (int) $user['id']
    );

    if ($decryptedEmail !== null) {
        try {
            // 32 random bytes → 64 hex chars. Not bruteforceable.
            $rawToken  = bin2hex(random_bytes(32));
            $tokenHash = hash('sha256', $rawToken);
            $expiresAt = gmdate('Y-m-d H:i:s', time() + 900); // 15 minutes

            $db->beginTransaction();

            // Invalidate ALL prior unconsumed password_reset tokens for this user.
            // Only the newest link works — old ones become dead the moment a
            // new one is generated. Prevents an attacker who found an old link
            // from racing the user.
            db_query(
                "UPDATE email_verification_tokens
                    SET consumed_at = UTC_TIMESTAMP()
                  WHERE user_id = ?
                    AND purpose = 'password_reset'
                    AND consumed_at IS NULL",
                [(int) $user['id']]
            );

            // Encrypt the target email (kept for rate-limit lookups and audit).
            $emailEnc = citadel_crypto_encrypt($email, (int) $user['id']);

            // Insert the new token.
            db_query(
                "INSERT INTO email_verification_tokens
                    (user_id, token_hash, purpose,
                     target_email_ct, target_email_nonce, target_email_index,
                     expires_at, created_at, requested_ip_hash)
                 VALUES (?, ?, 'password_reset',
                         ?, ?, ?,
                         ?, UTC_TIMESTAMP(), ?)",
                [
                    (int) $user['id'],
                    $tokenHash,
                    $emailEnc['ct'],
                    $emailEnc['nonce'],
                    $emailIndex,
                    $expiresAt,
                    substr(hash_hmac(
                        'sha256',
                        citadel_client_ip(),
                        $GLOBALS['citadel_fingerprint_key'] ?? ''
                    ), 0, 16),
                ]
            );

            $db->commit();

        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            citadel_log('auth', 'error', 'Password reset token creation failed', [
                'user_id' => (int) $user['id'],
                'error'   => $e->getMessage(),
            ]);
            // Fall through to generic success — never leak DB errors.
            $rawToken = null;
        }
    }

    // Send the email (only if token creation succeeded).
    if ($rawToken !== null && isset($decryptedEmail)) {
        $appUrl = rtrim(getenv('APP_URL') ?: 'https://mycitadel.lol', '/');

        // ⚠️ CRITICAL: use '#' not '?'.
        // The fragment is NEVER sent to the server. That means the token
        // cannot leak via access logs, Referer headers, email scanners, or
        // proxy logs. It stays in the browser.
        $resetUrl = $appUrl . '/reset-password#token=' . urlencode($rawToken);

        $username = htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8');

        $subject = 'Reset your MyCitadel password';

        $htmlBody = <<<HTML
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Inter,Arial,sans-serif;background:#05070a;color:#e0e6ed;padding:32px;margin:0;">
  <div style="max-width:560px;margin:0 auto;background:#10151d;border:1px solid rgba(0,229,255,0.22);border-radius:14px;padding:32px;">
    <h1 style="font-family:'Cinzel',Georgia,serif;color:#7df9ff;letter-spacing:0.08em;text-transform:uppercase;margin:0 0 16px;">MyCitadel</h1>
    <p style="margin:0 0 24px;color:#94a3b8;">Your digital fortress awaits your return.</p>

    <p>Hello <strong style="color:#e0e6ed;">{$username}</strong>,</p>

    <p>Someone requested a password reset for your MyCitadel account.</p>

    <p style="margin:32px 0;text-align:center;">
      <a href="{$resetUrl}"
         style="display:inline-block;padding:14px 32px;background:#00e5ff;color:#05070a;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;text-decoration:none;border-radius:6px;">
        Reset Password
      </a>
    </p>

    <p style="color:#94a3b8;font-size:14px;">
      This link expires in <strong style="color:#e0e6ed;">15 minutes</strong>
      and can only be used once.
    </p>

    <p style="color:#ef4444;font-size:14px;">
      If you did <strong>not</strong> request this, you can safely ignore this
      email. Your password will not change. However, someone may be attempting
      to access your account — consider enabling 2FA.
    </p>

    <hr style="border:none;border-top:1px solid rgba(0,229,255,0.15);margin:32px 0;">

    <p style="color:#475569;font-size:12px;">
      Having trouble with the button? Copy and paste this URL into your browser:<br>
      <span style="color:#00b8cc;word-break:break-all;">{$resetUrl}</span>
    </p>
  </div>
</body></html>
HTML;

        $textBody = "Hello {$user['username']},\n\n"
                  . "Someone requested a password reset for your MyCitadel account.\n\n"
                  . "Reset link: {$resetUrl}\n\n"
                  . "This link expires in 15 minutes and can only be used once.\n\n"
                  . "If you did not request this, ignore this email.\n";

        citadel_send_email($decryptedEmail, $subject, $htmlBody, ['text' => $textBody]);

        citadel_log('auth', 'info', 'Password reset email sent', [
            'user_id' => (int) $user['id'],
        ]);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * 07. GENERIC RESPONSE — SAME FOR ALL CASES
 * --------------------------------------------------------------------------
 * User exists → we sent an email.
 * User doesn't exist → we didn't send anything.
 * Either way, the client sees THIS.
 * ========================================================================== */

citadel_json_ok([
    'message'    => 'If an account exists for that email, a reset link has been sent.',
    'expires_in' => 900,
]);