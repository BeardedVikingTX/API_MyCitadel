<?php
/* ============================================================================
 * ███ USERS/DELETE_ACCOUNT.PHP ███
 * Route : POST /v1/users/delete_account
 * Body  : {
 *   "password":             "...",
 *   "confirmation_phrase":  "DELETE MY ACCOUNT"
 * }
 *
 * STEP 1 OF 2. Validates intent, sends a confirmation email.
 * Nothing is destroyed yet — the user must click the email link.
 *
 * WHY TWO STEPS:
 *   Account deletion is irreversible. A session hijack (stolen cookie, XSS,
 *   etc.) could let an attacker destroy an account. The email step means
 *   the attacker also needs access to the user's email — much harder.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/argon2.php';
require_once CITADEL_CONFIG . '/mailer.php';

citadel_rate_limit('delete_account_request', 3, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

$password = citadel_input_string('password', null, 1024);
$phrase   = citadel_input_string('confirmation_phrase', null, 64);

if ($password === null || $password === '') {
    citadel_json_error('password_required', 'Your password is required.', 400);
}

// The exact phrase users must type to confirm
const DELETE_CONFIRMATION_PHRASE = 'DELETE MY ACCOUNT';

if ($phrase !== DELETE_CONFIRMATION_PHRASE) {
    citadel_json_error('confirmation_mismatch',
        'Type "DELETE MY ACCOUNT" exactly to confirm.', 400);
}

// Verify password
$user = db_one(
    'SELECT id, username, email_ct, email_nonce, password_hash
       FROM users WHERE id = ? LIMIT 1',
    [$me]
);

if ($user === null) {
    citadel_session_destroy();
    citadel_json_error('account_missing', 'Account not found.', 401);
}

if (!citadel_verify_password($password, $user['password_hash'])) {
    citadel_log('security', 'warning', 'Account deletion: wrong password', [
        'user_id' => $me,
    ]);
    citadel_json_error('invalid_password', 'Incorrect password.', 403);
}

// Generate token
$rawToken  = bin2hex(random_bytes(32));
$tokenHash = hash('sha256', $rawToken);
$expiresAt = gmdate('Y-m-d H:i:s', time() + 3600); // 1 hour

try {
    $db = db();
    $db->beginTransaction();

    // Invalidate prior un-consumed deletion tokens
    db_query(
        "UPDATE email_verification_tokens
            SET consumed_at = UTC_TIMESTAMP()
          WHERE user_id = ? AND purpose = 'account_deletion' AND consumed_at IS NULL",
        [$me]
    );

    db_query(
        "INSERT INTO email_verification_tokens
            (user_id, token_hash, purpose, expires_at, created_at, requested_ip_hash)
         VALUES (?, ?, 'account_deletion', ?, UTC_TIMESTAMP(), ?)",
        [
            $me,
            $tokenHash,
            $expiresAt,
            substr(hash_hmac('sha256', citadel_client_ip(),
                $GLOBALS['citadel_fingerprint_key'] ?? ''), 0, 16),
        ]
    );

    $db->commit();
} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('security', 'error', 'Deletion token creation failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('internal_error', 'Could not process request.', 500);
}

// Send the email
$email = citadel_crypto_decrypt($user['email_ct'], $user['email_nonce'], $me);
if ($email !== null) {
    $appUrl   = rtrim(getenv('APP_URL') ?: 'https://mycitadel.lol', '/');
    $confirm  = $appUrl . '/delete-account?token=' . urlencode($rawToken);
    $username = htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8');

    $subject  = 'Confirm account deletion — MyCitadel';
    $htmlBody = <<<HTML
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Inter,Arial,sans-serif;background:#05070a;color:#e0e6ed;padding:32px;margin:0;">
  <div style="max-width:560px;margin:0 auto;background:#10151d;border:1px solid rgba(239,68,68,0.4);border-radius:14px;padding:32px;">
    <h1 style="font-family:'Cinzel',Georgia,serif;color:#7df9ff;letter-spacing:0.08em;text-transform:uppercase;margin:0 0 16px;">MyCitadel</h1>
    <p style="color:#ef4444;font-weight:700;font-size:18px;">⚠️ Account Deletion Request</p>

    <p>Hello <strong>{$username}</strong>,</p>

    <p>You requested that your MyCitadel account be permanently destroyed.</p>

    <p><strong>This action is irreversible.</strong> When confirmed:</p>
    <ul>
      <li>All your posts, comments, and reactions will be destroyed</li>
      <li>All your connections will be severed</li>
      <li>Your reputation points will be removed from the platform</li>
      <li>Your connections will lose the reputation they earned from connecting with you</li>
      <li>All your data will be shredded from our database</li>
    </ul>

    <p>To confirm, click below:</p>

    <p style="margin:32px 0;text-align:center;">
      <a href="{$confirm}"
         style="display:inline-block;padding:14px 32px;background:#ef4444;color:#ffffff;font-weight:700;letter-spacing:0.14em;text-transform:uppercase;text-decoration:none;border-radius:6px;">
        Confirm Deletion
      </a>
    </p>

    <p style="color:#94a3b8;font-size:14px;">
      This link expires in 1 hour. If you did not request this, ignore this
      email and change your password — someone may have access to your account.
    </p>
  </div>
</body></html>
HTML;

    citadel_send_email($email, $subject, $htmlBody);
}

citadel_log('security', 'info', 'Account deletion requested', ['user_id' => $me]);

citadel_json_ok([
    'message'    => 'Confirmation email sent. Click the link to complete deletion.',
    'expires_in' => 3600,
]);