<?php
/* ============================================================================
 * ███ AUTH/2FA/VERIFY.PHP ███
 * Route : POST /v1/auth/2fa/verify
 * Body  : { "code": "123456" }
 *
 * STEP 2 of 2. Verifies the code the user scanned, enables 2FA,
 * generates recovery codes, awards the Guardian badge (+1500 rep).
 *
 * Recovery codes are returned ONCE, in plaintext. We only store hashes.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/totp.php';
require_once CITADEL_CONFIG . '/badges.php';
require_once CITADEL_CONFIG . '/reputation.php';

citadel_rate_limit('2fa_verify', 10, 600);   // 10 attempts per 10 min
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$code = citadel_input_string('code', null, 16);

if ($code === null || !preg_match('/^\d{6}$/', $code)) {
    citadel_json_error('invalid_code', 'Enter the 6-digit code from your authenticator.', 400);
}

$row = db_one(
    'SELECT two_fa_enabled, two_fa_secret_ct, two_fa_secret_nonce
       FROM users WHERE id = ? LIMIT 1',
    [$me]
);

if ($row === null) {
    citadel_session_destroy();
    citadel_json_error('account_missing', 'Account not found.', 401);
}

if ((int) $row['two_fa_enabled'] === 1) {
    citadel_json_error('already_enabled', 'Two-factor is already enabled.', 409);
}

if (empty($row['two_fa_secret_ct']) || empty($row['two_fa_secret_nonce'])) {
    citadel_json_error('no_setup', 'No pending 2FA setup. Start over.', 409);
}

// Decrypt the pending secret
$secretBytes = citadel_crypto_decrypt(
    $row['two_fa_secret_ct'],
    $row['two_fa_secret_nonce'],
    $me
);

if ($secretBytes === null) {
    citadel_log('security', 'error', '2FA verify: decrypt failed', ['user_id' => $me]);
    citadel_json_error('internal_error', 'Could not verify code.', 500);
}

// Verify the code
if (!citadel_totp_verify($secretBytes, $code)) {
    citadel_log('security', 'warning', '2FA verify: wrong code', ['user_id' => $me]);
    citadel_json_error('invalid_code', 'That code did not match. Try the next one.', 400);
}

// ── Enable 2FA ────────────────────────────────────────────────────────────
$recovery = citadel_totp_generate_recovery_codes();
$recoveryEnc = citadel_crypto_encrypt(
    json_encode($recovery['hashes'], JSON_UNESCAPED_SLASHES),
    $me
);

$db = db();
$db->beginTransaction();

try {
    db_query(
        'UPDATE users
            SET two_fa_enabled = 1,
                two_fa_enabled_at = UTC_TIMESTAMP(),
                two_fa_recovery_codes_ct = ?,
                two_fa_recovery_codes_nonce = ?,
                updated_at = UTC_TIMESTAMP()
          WHERE id = ?',
        [$recoveryEnc['ct'], $recoveryEnc['nonce'], $me]
    );

    // Award the Guardian badge (+1500 rep, idempotent)
    try {
        award_badge($me, 'two_factor_enabled', 'enabled TOTP');
    } catch (Throwable $e) {
        // Badge award failure should not roll back the enable
        citadel_log('security', 'warning', '2FA badge award failed', [
            'user_id' => $me, 'error' => $e->getMessage(),
        ]);
    }

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('security', 'error', '2FA enable failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('enable_failed', 'Could not enable two-factor.', 500);
}

citadel_log('security', 'info', '2FA enabled', ['user_id' => $me]);

citadel_json_ok([
    'two_fa_enabled'  => true,
    'recovery_codes'  => $recovery['plain'],   // ONE TIME ONLY
    'reputation_earned' => 1500,
    'message'         => 'Two-factor enabled. Save your recovery codes NOW. '
                       . 'They will not be shown again.',
]);