<?php
/* ============================================================================
 * ███ AUTH/2FA/SETUP.PHP ███
 * Route : POST /v1/auth/2fa/setup
 * Body  : { "password": "..." }
 *
 * STEP 1 of 2. Generates a fresh secret and returns the otpauth:// URL
 * for the user's authenticator app. Does NOT enable 2FA yet.
 *
 * Requires current password because 2FA is a security-critical change.
 * A session hijacker without the password cannot initiate setup.
 *
 * If the user already has 2FA enabled, returns an error and asks them to
 * disable first — re-setup is only allowed when disabled.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/argon2.php';
require_once CITADEL_CONFIG . '/totp.php';

citadel_rate_limit('2fa_setup', 5, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

$password = citadel_input_string('password', null, 1024);
if ($password === null || $password === '') {
    citadel_json_error('password_required', 'Your current password is required.', 400);
}

$user = db_one(
    'SELECT id, username, email_ct, email_nonce, password_hash,
            two_fa_enabled
       FROM users WHERE id = ? LIMIT 1',
    [$me]
);

if ($user === null) {
    citadel_session_destroy();
    citadel_json_error('account_missing', 'Account not found.', 401);
}

// Verify password
if (!citadel_verify_password($password, $user['password_hash'])) {
    citadel_log('security', 'warning', '2FA setup: wrong password', ['user_id' => $me]);
    citadel_json_error('invalid_password', 'Incorrect password.', 403);
}

// Already enabled? Refuse.
if ((int) $user['two_fa_enabled'] === 1) {
    citadel_json_error('already_enabled',
        'Two-factor authentication is already enabled. Disable it first to set up a new one.',
        409);
}

// Generate fresh secret
$secretBytes = citadel_totp_generate_secret();

// Encrypt and store (unverified — two_fa_enabled stays 0)
$enc = citadel_crypto_encrypt($secretBytes, $me);

try {
    db_query(
        'UPDATE users
            SET two_fa_secret_ct = ?, two_fa_secret_nonce = ?,
                two_fa_recovery_codes_ct = NULL,
                two_fa_recovery_codes_nonce = NULL
          WHERE id = ?',
        [$enc['ct'], $enc['nonce'], $me]
    );
} catch (Throwable $e) {
    citadel_log('security', 'error', '2FA secret storage failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('storage_failed', 'Could not generate 2FA secret.', 500);
}

// Build the otpauth URL for the QR code
// Build the otpauth URL for the QR code
$account = $user['username'];
$otpauth = citadel_totp_otpauth_url($secretBytes, $account, 'MyCitadel');
$base32  = citadel_base32_encode($secretBytes);

// Generate QR code as an inline SVG data URI
$qrCodeDataUri = null;
try {
    if (class_exists(\chillerlan\QRCode\QRCode::class)) {
        $options = new \chillerlan\QRCode\QROptions([
            'version'    => 5,
            'outputType' => \chillerlan\QRCode\QRCode::OUTPUT_MARKUP_SVG,
            'eccLevel'   => \chillerlan\QRCode\QRCode::ECC_L,
        ]);
        $qrCode = new \chillerlan\QRCode\QRCode($options);
        $qrCodeDataUri = $qrCode->render($otpauth);
    }
} catch (Throwable $e) {
    citadel_log('security', 'warning', 'QR code generation failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
}

citadel_log('security', 'info', '2FA setup initiated', ['user_id' => $me]);

citadel_json_ok([
    'otpauth_url' => $otpauth,
    'secret'      => $base32,
    'qr_code'     => $qrCodeDataUri,
    'account'     => $account,
    'issuer'      => 'MyCitadel',
    'message'     => 'Scan the QR code with your authenticator app, then enter the 6-digit code to confirm.',
]);