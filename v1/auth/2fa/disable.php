<?php
/* ============================================================================
 * ███ AUTH/2FA/DISABLE.PHP ███
 * Route : POST /v1/auth/2fa/disable
 * Body  : { "password": "...", "code": "123456" }   // code OR recovery
 *
 * Requires: current password AND (TOTP code OR valid recovery code).
 * This is intentionally strict — disabling 2FA is a downgrade of security.
 *
 * The Guardian badge and its 1500 rep are NOT removed on disable.
 * award_badge() is idempotent, so re-enabling does not farm rep.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/argon2.php';
require_once CITADEL_CONFIG . '/totp.php';

citadel_rate_limit('2fa_disable', 10, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me = (int) citadel_current_user_id();

$password = citadel_input_string('password', null, 1024);
$code     = citadel_input_string('code', null, 32);

if ($password === null || $password === '') {
    citadel_json_error('password_required', 'Your current password is required.', 400);
}
if ($code === null || $code === '') {
    citadel_json_error('code_required', 'Enter a 6-digit code or a recovery code.', 400);
}

$row = db_one(
    'SELECT password_hash, two_fa_enabled,
            two_fa_secret_ct, two_fa_secret_nonce,
            two_fa_recovery_codes_ct, two_fa_recovery_codes_nonce
       FROM users WHERE id = ? LIMIT 1',
    [$me]
);

if ($row === null) {
    citadel_session_destroy();
    citadel_json_error('account_missing', 'Account not found.', 401);
}

if (!citadel_verify_password($password, $row['password_hash'])) {
    citadel_log('security', 'warning', '2FA disable: wrong password', ['user_id' => $me]);
    citadel_json_error('invalid_password', 'Incorrect password.', 403);
}

if ((int) $row['two_fa_enabled'] !== 1) {
    citadel_json_error('not_enabled', 'Two-factor is not enabled.', 409);
}

// Try TOTP first, then recovery code
$verified = false;
$usedRecoveryIndex = null;
$remainingHashes = null;

if (preg_match('/^\d{6}$/', $code)) {
    $secretBytes = citadel_crypto_decrypt(
        $row['two_fa_secret_ct'], $row['two_fa_secret_nonce'], $me
    );
    if ($secretBytes !== null && citadel_totp_verify($secretBytes, $code)) {
        $verified = true;
    }
} else {
    // Recovery code path
    $codesJson = citadel_crypto_decrypt(
        $row['two_fa_recovery_codes_ct'], $row['two_fa_recovery_codes_nonce'], $me
    );
    if ($codesJson !== null) {
        $hashes = json_decode($codesJson, true);
        if (is_array($hashes)) {
            $idx = citadel_totp_verify_recovery_code($code, $hashes);
            if ($idx !== null) {
                $verified = true;
                $usedRecoveryIndex = $idx;
                // Remove the used code
                array_splice($hashes, $idx, 1);
                $remainingHashes = $hashes;
            }
        }
    }
}

if (!$verified) {
    citadel_log('security', 'warning', '2FA disable: wrong code', ['user_id' => $me]);
    citadel_json_error('invalid_code', 'That code did not match.', 403);
}

// ── Disable ───────────────────────────────────────────────────────────────
$db = db();
$db->beginTransaction();

try {
    db_query(
        'UPDATE users
            SET two_fa_enabled = 0,
                two_fa_secret_ct = NULL,
                two_fa_secret_nonce = NULL,
                two_fa_recovery_codes_ct = NULL,
                two_fa_recovery_codes_nonce = NULL,
                two_fa_enabled_at = NULL,
                updated_at = UTC_TIMESTAMP()
          WHERE id = ?',
        [$me]
    );

    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('security', 'error', '2FA disable failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('disable_failed', 'Could not disable two-factor.', 500);
}

citadel_log('security', 'info', '2FA disabled', [
    'user_id' => $me,
    'via_recovery' => $usedRecoveryIndex !== null,
]);

citadel_json_ok([
    'two_fa_enabled' => false,
    'message'        => 'Two-factor disabled. Your account is less secure now.',
]);