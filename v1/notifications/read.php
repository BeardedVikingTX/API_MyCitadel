<?php
/* ============================================================================
 * ███ NOTIFICATIONS/READ.PHP ███
 * Route : POST /v1/notifications/read
 * Body  : { "id": 5 }         ← mark one
 *         { "all": true }     ← mark all
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('notif_read', 120, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me      = (int) citadel_current_user_id();
$body    = citadel_input_json();
$readAll = !empty($body['all']);
$notifId = isset($body['id']) ? (int) $body['id'] : null;

if ($readAll) {
    $affected = db_query(
        'UPDATE notifications SET read_at = UTC_TIMESTAMP()
          WHERE user_id = ? AND read_at IS NULL',
        [$me]
    )->rowCount();

    citadel_json_ok(['marked' => $affected]);
}

if ($notifId === null || $notifId <= 0) {
    citadel_json_error('missing_id', 'Provide "id" or "all": true.', 400);
}

$affected = db_query(
    'UPDATE notifications SET read_at = UTC_TIMESTAMP()
      WHERE id = ? AND user_id = ? AND read_at IS NULL',
    [$notifId, $me]
)->rowCount();

citadel_json_ok(['marked' => $affected]);