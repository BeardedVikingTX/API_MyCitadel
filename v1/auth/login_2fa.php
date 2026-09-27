<?php
/* ============================================================================
 * ███ AUTH/LOGIN_2FA.PHP ███
 * Route : POST /v1/auth/login_2fa
 * Body  : { "code": "123456" }   // code OR recovery code
 *
 * Second step of login when the user has 2FA enabled.
 *
 * The pending user_id is stored in the session by login.php. We never trust
 * a client-supplied user_id — that would be a trivial 2FA bypass.
 *
 * Wrong code: increments attempt counter in the session.
 * 5 wrong attempts: clears pending state, forces full re-login.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/crypto.php';
require_once CITADEL_CONFIG . '/totp.php';
require_once CITADEL_CONFIG . '/lockout.php';

citadel_rate_limit('login_2fa', 15, 300);
citadel_require_csrf();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

// ── Load pending state from session ───────────────────────────────────────
$pending = $_SESSION['_citadel']['two_fa_pending'] ?? null;

if (!is_array($pending)
    || empty($pending['user_id'])
    || empty($pending['expires'])
) {
    citadel_json_error('no_pending',
        'No pending 2FA session. Please log in again.', 401);
}

if (time() > (int) $pending['expires']) {
    unset($_SESSION['_citadel']['two_fa_pending']);
    citadel_json_error('expired',
        'Your 2FA session expired. Please log in again.', 401);
}

if ((int) ($pending['attempts'] ?? 0) >= 5) {
    unset($_SESSION['_citadel']['two_fa_pending']);
    citadel_log('security', 'warning', '2FA pending exceeded attempts', []);
    citadel_json_error('too_many_attempts',
        'Too many wrong codes. Please log in again.', 429);
}

$userId = (int) $pending['user_id'];

// ── Read + validate the code ──────────────────────────────────────────────
$code = citadel_input_string('code', null, 32);
if ($code === null || $code === '') {
    citadel_json_error('code_required', 'Enter a code.', 400);
}

$row = db_one(
    'SELECT id, username, is_premium, is_active, is_banned,
            two_fa_enabled, two_fa_secret_ct, two_fa_secret_nonce,
            two_fa_recovery_codes_ct, two_fa_recovery_codes_nonce
       FROM users WHERE id = ? LIMIT 1',
    [$userId]
);

if ($row === null || (int) $row['two_fa_enabled'] !== 1) {
    unset($_SESSION['_citadel']['two_fa_pending']);
    citadel_json_error('no_pending', 'Please log in again.', 401);
}

if ((int) $row['is_active'] !== 1 || (int) $row['is_banned'] === 1) {
    unset($_SESSION['_citadel']['two_fa_pending']);
    citadel_json_error('invalid_credentials', 'Invalid credentials.', 401);
}

// ── Verify: TOTP first, then recovery code ────────────────────────────────
$verified = false;
$usedRecovery = false;
$remainingRecoveryHashes = null;

if (preg_match('/^\d{6}$/', $code)) {
    $secretBytes = citadel_crypto_decrypt(
        $row['two_fa_secret_ct'], $row['two_fa_secret_nonce'], $userId
    );
    if ($secretBytes !== null && citadel_totp_verify($secretBytes, $code)) {
        $verified = true;
    }
} else {
    // Recovery code path — single-use
    $codesJson = citadel_crypto_decrypt(
        $row['two_fa_recovery_codes_ct'], $row['two_fa_recovery_codes_nonce'], $userId
    );
    if ($codesJson !== null) {
        $hashes = json_decode($codesJson, true);
        if (is_array($hashes)) {
            $idx = citadel_totp_verify_recovery_code($code, $hashes);
            if ($idx !== null) {
                $verified = true;
                $usedRecovery = true;
                array_splice($hashes, $idx, 1);
                $remainingRecoveryHashes = $hashes;
            }
        }
    }
}

// ── Handle failure ────────────────────────────────────────────────────────
if (!$verified) {
    $attempts = (int) ($pending['attempts'] ?? 0) + 1;
    $_SESSION['_citadel']['two_fa_pending']['attempts'] = $attempts;

    citadel_log('security', 'warning', '2FA login: wrong code', [
        'user_id' => $userId, 'attempt' => $attempts,
    ]);

    // Also apply account-lockout tracking so botnet attacks are limited
    citadel_lockout_record_attempt(
        '2fa:' . $userId,
        $userId,
        false,
        'wrong_2fa'
    );

    if ($attempts >= 5) {
        unset($_SESSION['_citadel']['two_fa_pending']);
        citadel_json_error('too_many_attempts',
            'Too many wrong codes. Please log in again.', 429);
    }

    $remaining = 5 - $attempts;
    citadel_json_error('invalid_code',
        "That code did not match. {$remaining} attempt(s) remaining.", 400);
}

// ── Success ───────────────────────────────────────────────────────────────
// If a recovery code was used, persist the updated set
if ($usedRecovery && $remainingRecoveryHashes !== null) {
    try {
        $enc = citadel_crypto_encrypt(
            json_encode($remainingRecoveryHashes, JSON_UNESCAPED_SLASHES),
            $userId
        );
        db_query(
            'UPDATE users SET two_fa_recovery_codes_ct = ?, two_fa_recovery_codes_nonce = ? WHERE id = ?',
            [$enc['ct'], $enc['nonce'], $userId]
        );
    } catch (Throwable $e) {
        citadel_log('security', 'error', 'Recovery code persistence failed', [
            'user_id' => $userId, 'error' => $e->getMessage(),
        ]);
        // Non-fatal — allow login anyway, but log
    }
}

// Clear pending state, establish authenticated session
unset($_SESSION['_citadel']['two_fa_pending']);

citadel_session_login($userId);
citadel_hint_set();

// Clear recent 2FA failures for this user
citadel_lockout_clear_prior_failures('2fa:' . $userId);

// Fetch stats
$rep = (int) (db_scalar(
    'SELECT COALESCE(reputation_points, 0) FROM user_stats WHERE user_id = ? LIMIT 1',
    [$userId]
) ?? 0);

citadel_log('security', 'info', '2FA login successful', [
    'user_id' => $userId,
    'via_recovery' => $usedRecovery,
]);

citadel_json_ok([
    'user' => [
        'id'         => (int) $row['id'],
        'username'   => (string) $row['username'],
        'reputation' => $rep,
        'premium'    => (bool) $row['is_premium'],
    ],
    'csrf_token'      => citadel_csrf_token(),
    'via_recovery_code' => $usedRecovery,
    'recovery_codes_remaining' => $usedRecovery && $remainingRecoveryHashes !== null
        ? count($remainingRecoveryHashes)
        : null,
]);