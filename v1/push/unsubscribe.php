<?php
/* ============================================================================
 * ███ PUSH/UNSUBSCRIBE.PHP ███
 * Route : POST /v1/push/unsubscribe
 * Auth  : Required
 * CSRF  : Required
 *
 * Removes a push subscription (permanent, not just deactivated).
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('push_unsubscribe', 10, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$endpoint = isset($body['endpoint']) && is_string($body['endpoint']) ? $body['endpoint'] : null;

if (!$endpoint) {
    citadel_json_error('missing_endpoint', 'endpoint is required.', 400);
}

$endpointHash = hash('sha256', $endpoint);

// Only allow deleting your OWN subscriptions
$deleted = db_query(
    'DELETE FROM push_subscriptions
      WHERE endpoint_hash = ? AND user_id = ?',
    [$endpointHash, $me]
)->rowCount();

citadel_log('push', 'info', 'Push unsubscribe', [
    'user_id'       => $me,
    'endpoint_hash' => substr($endpointHash, 0, 12),
    'deleted'       => $deleted,
]);

citadel_json_ok([
    'message' => $deleted > 0 ? 'Subscription removed.' : 'No matching subscription.',
    'deleted' => $deleted,
]);