<?php
/* ============================================================================
 * ███ CONNECTIONS/ACCEPT.PHP ███
 * Route : POST /v1/connections/accept
 * Body  : { "user_id": 5 }
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';
require_once CITADEL_CONFIG . '/notifications.php';

citadel_rate_limit('conn_accept', 30, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me       = (int) citadel_current_user_id();
$targetId = citadel_input_int('user_id');

if ($targetId === null || $targetId <= 0) {
    citadel_json_error('invalid_user', 'A valid user_id is required.', 400);
}

$existing = citadel_rel_get($me, $targetId);

if ($existing === null) {
    citadel_json_error('no_request', 'No pending request from this user.', 404);
}

if ($existing['state'] === 'blocked') {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

if ($existing['state'] === 'connected') {
    citadel_json_ok(['state' => 'connected', 'message' => 'Already connected.']);
}

if ($existing['state'] !== 'pending') {
    citadel_json_error('no_request', 'No pending request from this user.', 404);
}

// Only the recipient (the one who did NOT initiate) can accept
if ((int) $existing['initiated_by'] === $me) {
    citadel_json_error('cannot_accept_own',
        'You cannot accept your own request.', 403);
}

try {
    citadel_rel_set($me, $targetId, 'connected', (int) $existing['initiated_by']);

    // Bump connection counters on both sides
    db_query('UPDATE user_stats SET connection_count = connection_count + 1 WHERE user_id = ?', [$me]);
    db_query('UPDATE user_stats SET connection_count = connection_count + 1 WHERE user_id = ?', [$targetId]);

    citadel_notify(
        $targetId,
        'connection_accepted',
        'Connection accepted',
        null,
        $me,
        ['user_id' => $me],
        '/connections'
    );

    citadel_log('api', 'info', 'Connection accepted', [
        'by'   => $me,
        'with' => $targetId,
    ]);

} catch (Throwable $e) {
    citadel_log('api', 'error', 'Connection accept failed', [
        'me'    => $me,
        'other' => $targetId,
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('accept_failed', 'Could not accept the request.', 500);
}

citadel_json_ok([
    'state'   => 'connected',
    'message' => 'Connection established.',
]);