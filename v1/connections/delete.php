<?php
/* ============================================================================
 * ███ NOTIFICATIONS/DELETE.PHP ███
 * Route : POST /v1/notifications/delete
 * Body  : { "id": 5 }
 *
 * Removes a single notification owned by the current user.
 * Idempotent — deleting an already-deleted notification returns 0.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('notif_delete', 120, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$id = isset($body['id']) ? (int) $body['id'] : null;
if ($id === null || $id <= 0) {
    citadel_json_error('missing_id', 'Provide "id".', 400);
}

$deleted = db_query(
    'DELETE FROM notifications WHERE id = ? AND user_id = ?',
    [$id, $me]
)->rowCount();

citadel_log('api', 'info', 'Notification deleted', [
    'user_id'         => $me,
    'notification_id' => $id,
    'deleted'         => $deleted,
]);

citadel_json_ok([
    'deleted' => $deleted,
]);