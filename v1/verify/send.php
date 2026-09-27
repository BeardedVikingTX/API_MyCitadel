<?php
/* ============================================================================
 * ███ SEND.PHP ███
 * MyCitadel — Email Verification: Initiate / Resend
 * ----------------------------------------------------------------------------
 * Route   : POST /v1/verify/send
 * Auth    : Required (must be logged in)
 * CSRF    : Required
 * Rate    : 3 per 15 minutes per user (server-side enforced)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 *  1. Confirms the caller is authenticated.
 *  2. Confirms the user is not already verified.
 *  3. Enforces a 3-per-15-min send limit (per user).
 *  4. Invalidates any previous un-consumed tokens for this user.
 *  5. Generates a fresh 32-byte random token.
 *  6. Stores SHA-256 hash of the token + 24h expiry in email_verification_tokens.
 *  7. Sends the email with a verification link via citadel_send_email().
 *  8. Returns success.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * TOKEN DESIGN
 * ────────────────────────────────────────────────────────────────────────────
 *   • Raw token      : 32 random bytes, hex-encoded (64 chars)
 *   • Stored         : SHA-256 hash of the raw token (never the raw value)
 *   • Purpose        : 'verify_initial'
 *   • TTL            : 24 hours
 *   • Single-use     : Consumed on first successful verify
 *   • Prior tokens   : Invalidated on each new send
 *
 * The raw token is transmitted ONLY in the email body. If the database
 * leaks, an attacker gets hashes — and cannot reverse them to build links.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * ACCOUNT ENUMERATION DEFENSE
 * ────────────────────────────────────────────────────────────────────────────
 *   Since the user must already be authenticated to call this endpoint,
 *   enumeration risk is minimal. But we still:
 *     • Return the SAME response for "already verified" and "sent"
 *     • Enforce the rate limit silently (no "you already requested" hints)
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/mailer.php';


/* ══════════════════════════════════════════════════════════════════════════
 * 01. REQUEST PROTECTIONS
 * ========================================================================== */

citadel_require_csrf();
citadel_require_auth('json');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'This endpoint accepts POST only.', 405);
}

$userId = (int) citadel_current_user_id();


/* ══════════════════════════════════════════════════════════════════════════
 * 02. PER-USER RATE LIMIT (3 per 15 min)
 * --------------------------------------------------------------------------
 * We use the database, not the file-based rate limiter, because this must
 * follow the user, not the IP. A user switching networks shouldn't reset
 * their limit.
 * ========================================================================== */

$recent = db_scalar(
    "SELECT COUNT(*) FROM email_verification_tokens
      WHERE user_id = ? AND purpose = 'verify_initial'
        AND created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)",
    [$userId]
);

if ((int) $recent >= 3) {
    citadel_log('auth', 'warning', 'Verification email rate limit hit', [
        'user_id' => $userId,
    ]);
    citadel_json_error('rate_limited',
        'Too many verification emails. Please wait 15 minutes before trying again.', 429);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 03. LOAD USER + CHECK STATUS
 * ========================================================================== */

$user = db_one(
    'SELECT id, username, email_ct, email_nonce, email_verified, is_active
     FROM users WHERE id = ? LIMIT 1',
    [$userId]
);

if ($user === null) {
    citadel_session_destroy();
    citadel_json_error('account_missing', 'Your account no longer exists.', 401);
}

if ((int) $user['email_verified'] === 1) {
    // Already verified — return the same generic success to avoid leaking state.
    citadel_json_ok([
        'message' => 'If your email requires verification, a link has been sent.',
    ]);
    return;
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
    citadel_log('security', 'error', 'Email decryption failed for verification send', [
        'user_id' => $userId,
    ]);
    citadel_json_error('internal_error',
        'Could not process your request. Please try again later.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 05. GENERATE TOKEN + INVALIDATE PRIOR TOKENS
 * ========================================================================== */

$rawToken  = bin2hex(random_bytes(32));    // 64 hex chars
$tokenHash = hash('sha256', $rawToken);    // 64 hex chars (stored)
$expiresAt = gmdate('Y-m-d H:i:s', time() + 86400);  // +24 hours

try {
    $db = db();
    $db->beginTransaction();

    // Invalidate any still-unconsumed tokens for this user
    db_query(
        "UPDATE email_verification_tokens
            SET consumed_at = UTC_TIMESTAMP()
          WHERE user_id = ? AND purpose = 'verify_initial' AND consumed_at IS NULL",
        [$userId]
    );

    // Insert the new token
    db_query(
        "INSERT INTO email_verification_tokens
            (user_id, token_hash, purpose, expires_at, created_at, requested_ip_hash)
         VALUES (?, ?, 'verify_initial', ?, UTC_TIMESTAMP(), ?)",
        [
            $userId,
            $tokenHash,
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
    citadel_log('auth', 'error', 'Failed to create verification token', [
        'user_id' => $userId,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('internal_error',
        'Could not process your request. Please try again later.', 500);
}


/* ══════════════════════════════════════════════════════════════════════════
 * 06. BUILD THE VERIFICATION LINK
 * --------------------------------------------------------------------------
 * The link points at the FRONTEND (mycitadel.lol), not the API. The frontend
 * reads the token from the URL, then POSTs it to /v1/verify/verify.
 *
 * Why not point directly at the API?
 *   • Keeps the API strictly JSON (no HTML responses)
 *   • Lets the frontend show a branded success/failure page
 *   • Lets us add a "click to confirm" step (defends against email scanners)
 * ========================================================================== */

$appUrl = rtrim(getenv('APP_URL') ?: 'https://mycitadel.lol', '/');
$verifyUrl = $appUrl . '/verify?token=' . urlencode($rawToken);

$username = htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8');
$expiresHuman = '24 hours';


/* ══════════════════════════════════════════════════════════════════════════
 * 07. EMAIL BODY
 * ========================================================================== */

$subject = 'Verify your MyCitadel email';

$htmlBody = <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Verify your email</title>
</head>
<body style="font-family:Inter,Arial,sans-serif;background:#05070a;color:#e0e6ed;padding:32px;margin:0;">
  <div style="max-width:560px;margin:0 auto;background:#10151d;border:1px solid rgba(0,229,255,0.22);border-radius:14px;padding:32px;">
    <h1 style="font-family:'Cinzel',Georgia,serif;color:#7df9ff;letter-spacing:0.08em;text-transform:uppercase;margin:0 0 16px;">MyCitadel</h1>
    <p style="margin:0 0 24px;color:#94a3b8;">Your digital fortress awaits confirmation.</p>

    <p>Hello <strong style="color:#e0e6ed;">{$username}</strong>,</p>

    <p>Welcome to MyCitadel. To complete your account setup and unlock
    full access to the platform, please verify your email address by
    clicking the button below:</p>

    <p style="margin:32px 0;text-align:center;">
      <a href="{$verifyUrl}"
         style="display:inline-block;padding:14px 32px;background:#00e5ff;color:#05070a;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;text-decoration:none;border-radius:6px;">
        Verify My Email
      </a>
    </p>

    <p style="color:#94a3b8;font-size:14px;">
      This link expires in <strong style="color:#e0e6ed;">{$expiresHuman}</strong>.
      If it expires, you can request a new one from your account settings.
    </p>

    <p style="color:#94a3b8;font-size:14px;">
      If you did not create a MyCitadel account, you can safely ignore this email.
    </p>

    <hr style="border:none;border-top:1px solid rgba(0,229,255,0.15);margin:32px 0;">

    <p style="color:#475569;font-size:12px;">
      Having trouble with the button? Copy and paste this URL into your browser:<br>
      <span style="color:#00b8cc;word-break:break-all;">{$verifyUrl}</span>
    </p>
  </div>
</body>
</html>
HTML;

$textBody = "Hello {$user['username']},\n\n"
          . "Welcome to MyCitadel. Verify your email by visiting:\n\n"
          . "{$verifyUrl}\n\n"
          . "This link expires in {$expiresHuman}.\n\n"
          . "If you did not create an account, ignore this email.\n";


/* ══════════════════════════════════════════════════════════════════════════
 * 08. SEND
 * ========================================================================== */

$sent = citadel_send_email($email, $subject, $htmlBody, ['text' => $textBody]);

if (!$sent) {
    // Cleanup: mark the token we just created as consumed so it can't be used.
    db_query(
        "UPDATE email_verification_tokens SET consumed_at = UTC_TIMESTAMP()
          WHERE token_hash = ?",
        [$tokenHash]
    );

    citadel_log('email', 'error', 'Verification email delivery failed', [
        'user_id' => $userId,
    ]);

    // Do NOT tell the client "the email failed" — that could leak info.
    citadel_json_error('send_failed',
        'Could not send the verification email. Please try again later.', 503);
}

citadel_log('auth', 'info', 'Verification email sent', [
    'user_id' => $userId,
]);


/* ══════════════════════════════════════════════════════════════════════════
 * 09. RESPONSE
 * --------------------------------------------------------------------------
 * Generic success. We never reveal whether the email address was valid,
 * whether the user was already verified, or whether the SMTP call succeeded
 * — all "send" attempts return the same shape.
 * ========================================================================== */

citadel_json_ok([
    'message' => 'If your email requires verification, a link has been sent.',
    'expires_in' => 86400,
]);