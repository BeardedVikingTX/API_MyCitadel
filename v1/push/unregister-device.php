<?php
/* ============================================================================
 * ███ PUSH/UNREGISTER-DEVICE.PHP ███
 * Route : POST /v1/push/unregister-device
 * Auth  : Required
 * CSRF  : Required
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('push_unregister_device', 20, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$token = isset($body['token']) && is_string($body['token']) ? trim($body['token']) : null;

if (!$token) {
    citadel_json_error('missing_token', 'token is required.', 400);
}

$tokenHash = hash('sha256', $token);

$deleted = db_query(
    'DELETE FROM push_subscriptions
      WHERE endpoint_hash = ?
        AND platform = "android"
        AND user_id = ?',
    [$tokenHash, $me]
)->rowCount();

citadel_log('push', 'info', 'Android device unregistered', [
    'user_id'       => $me,
    'endpoint_hash' => substr($tokenHash, 0, 12),
    'deleted'       => $deleted,
]);

citadel_json_ok([
    'message' => $deleted > 0 ? 'Device removed.' : 'No matching device.',
    'deleted' => $deleted,
]);