<?php
/* ============================================================================
 * ███ PUSH/REGISTER-DEVICE.PHP ███
 * Route : POST /v1/push/register-device
 * Auth  : Required
 * CSRF  : Required
 *
 * Registers an Android device's FCM token. Called by the app:
 *   • After login (or if the session is already valid on cold start)
 *   • Every time FirebaseMessagingService.onNewToken() fires
 *
 * Upserts by token — if the same device re-registers after a reinstall,
 * the row is updated rather than duplicated.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('push_register_device', 20, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$token    = isset($body['token'])    && is_string($body['token'])    ? trim($body['token']) : null;
$deviceId = isset($body['device_id']) && is_string($body['device_id']) ? trim($body['device_id']) : null;
$appVer   = isset($body['app_version']) && is_string($body['app_version']) ? $body['app_version'] : null;

if (!$token || strlen($token) < 40 || strlen($token) > 4096) {
    citadel_json_error('invalid_token', 'A valid FCM token is required.', 400);
}

$tokenHash = hash('sha256', $token);

// Optional: shorten the hash for a device_id column, or store it as-is.
// We use device_id as a secondary identifier to help the sender dedupe.
$deviceIdHash = $deviceId ? substr(hash('sha256', $deviceId), 0, 32) : null;

try {
    db_query(
        'INSERT INTO push_subscriptions
            (user_id, platform, endpoint_hash, endpoint, p256dh, auth_token,
             user_agent_hash, is_active)
         VALUES (?, "android", ?, ?, NULL, NULL, ?, 1)
         ON DUPLICATE KEY UPDATE
            user_id         = VALUES(user_id),
            platform        = "android",
            endpoint        = VALUES(endpoint),
            user_agent_hash = VALUES(user_agent_hash),
            is_active       = 1,
            last_error      = NULL,
            error_count     = 0',
        [$me, $tokenHash, $token, $deviceIdHash]
    );

    citadel_log('push', 'info', 'Android device registered for push', [
        'user_id'       => $me,
        'endpoint_hash' => substr($tokenHash, 0, 12),
        'app_version'   => $appVer,
    ]);

} catch (Throwable $e) {
    citadel_log('push', 'error', 'Android device registration failed', [
        'user_id' => $me,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('register_failed',
        'Could not register device.', 500);
}

citadel_json_ok(['message' => 'Device registered.']);