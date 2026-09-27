<?php
/* ============================================================================
 * ███ AUTH/2FA/STATUS.PHP ███
 * Route : GET /v1/auth/2fa/status
 * Returns whether 2FA is enabled + how many recovery codes remain.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';

citadel_rate_limit('2fa_status', 60, 60);
citadel_require_auth('json');

$me = (int) citadel_current_user_id();

$row = db_one(
    'SELECT two_fa_enabled, two_fa_enabled_at,
            two_fa_recovery_codes_ct, two_fa_recovery_codes_nonce
       FROM users WHERE id = ? LIMIT 1',
    [$me]
);

if ($row === null) {
    citadel_json_error('account_missing', 'Account not found.', 401);
}

$recoveryRemaining = 0;
if ((int) $row['two_fa_enabled'] === 1
    && !empty($row['two_fa_recovery_codes_ct'])
) {
    $json = citadel_crypto_decrypt(
        $row['two_fa_recovery_codes_ct'],
        $row['two_fa_recovery_codes_nonce'],
        $me
    );
    if ($json !== null) {
        $arr = json_decode($json, true);
        if (is_array($arr)) $recoveryRemaining = count($arr);
    }
}

citadel_json_ok([
    'two_fa_enabled'         => (int) $row['two_fa_enabled'] === 1,
    'two_fa_enabled_at'      => $row['two_fa_enabled_at']
        ? gmdate('c', strtotime((string) $row['two_fa_enabled_at']))
        : null,
    'recovery_codes_remaining' => $recoveryRemaining,
]);