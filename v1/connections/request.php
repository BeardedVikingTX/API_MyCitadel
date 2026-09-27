<?php
/* ============================================================================
 * ███ CONNECTIONS/REQUEST.PHP ███
 * Route : POST /v1/connections/request
 * Body  : { "user_id": 5, "message": "optional intro" }
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';
require_once CITADEL_CONFIG . '/notifications.php';

citadel_rate_limit('conn_request', 20, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me       = (int) citadel_current_user_id();
$targetId = citadel_input_int('user_id');
$message  = citadel_input_string('message', null, 255);

if ($targetId === null || $targetId <= 0) {
    citadel_json_error('invalid_user', 'A valid user_id is required.', 400);
}
if ($targetId === $me) {
    citadel_json_error('cannot_request_self', 'You cannot connect with yourself.', 400);
}

// Verify target exists and is visible
$target = db_one(
    'SELECT u.id, u.username, u.is_active, u.is_banned, p.visibility
       FROM users u
       LEFT JOIN user_profiles p ON p.user_id = u.id
      WHERE u.id = ? LIMIT 1',
    [$targetId]
);

if ($target === null
    || (int) $target['is_active'] !== 1
    || (int) $target['is_banned'] === 1) {
    // Don't reveal existence — same response as blocked
    citadel_json_error('user_not_found', 'User not found.', 404);
}

$existing = citadel_rel_get($me, $targetId);

if ($existing !== null) {
    switch ($existing['state']) {
        case 'blocked':
            // Silent 404 — never reveal a block
            citadel_json_error('user_not_found', 'User not found.', 404);

        case 'connected':
            citadel_json_error('already_connected',
                'You are already connected with this user.', 409);

        case 'pending':
            if ((int) $existing['initiated_by'] === $me) {
                citadel_json_error('already_requested',
                    'You have already sent a connection request.', 409);
            }
            // They requested us first — refuse so the UI shows Accept/Deny
            citadel_json_error('incoming_request_exists',
                'This user has already sent you a connection request. Accept or deny it.', 409);
    }
}

// Also check the target's visibility preference
if ($target['visibility'] === 'hidden') {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

// Create the relationship
try {
    citadel_rel_set($me, $targetId, 'pending', $me, $message);

    citadel_notify(
        $targetId,
        'connection_request',
        'New connection request',
        null,
        $me,
        ['user_id' => $me, 'username' => citadel_current_username()],
        '/connections/pending'
    );

    citadel_log('api', 'info', 'Connection requested', [
        'from' => $me,
        'to'   => $targetId,
    ]);

} catch (Throwable $e) {
    citadel_log('api', 'error', 'Connection request failed', [
        'from'  => $me,
        'to'    => $targetId,
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('request_failed',
        'Could not send the connection request. Please try again.', 500);
}

citadel_json_ok([
    'state'   => 'pending',
    'message' => 'Connection request sent.',
]);