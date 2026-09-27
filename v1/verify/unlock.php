<?php
/* ============================================================================
 * ███ UNLOCK.PHP ███
 * MyCitadel — One-Click Account Unlock
 * ----------------------------------------------------------------------------
 * Route : POST /v1/verify/unlock
 * Auth  : None (the token IS the auth)
 * CSRF  : Required
 *
 * WHAT IT DOES
 *   Consumes an unlock token from a lockout alert email. Clears all active
 *   lockouts for the associated user.
 *
 *   This is the recovery path for a legitimate user who was locked out by
 *   an attacker's failed attempts. They click the link in their email, and
 *   their account is immediately unlocked.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/lockout.php';

citadel_rate_limit('unlock', 20, 3600);
citadel_require_csrf();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$token = citadel_input_string('token', null, 128);

if ($token === null || !preg_match('/^[a-f0-9]{64}$/i', $token)) {
    citadel_json_error('invalid_token', 'Invalid or expired unlock link.', 400);
}

$userId = citadel_lockout_consume_unlock_token($token);

if ($userId === null) {
    citadel_json_error('invalid_token', 'Invalid or expired unlock link.', 400);
}

citadel_log('security', 'info', 'Account unlocked via email link', [
    'user_id' => $userId,
]);

citadel_json_ok([
    'message' => 'Your account has been unlocked. You may now log in.',
]);