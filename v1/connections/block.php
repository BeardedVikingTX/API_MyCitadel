<?php
/* ============================================================================
 * ███ CONNECTIONS/BLOCK.PHP ███
 * Route : POST /v1/connections/block
 * Body  : { "user_id": 5, "reason": "optional" }
 *
 * Handles deny / sever / block — all three are the same operation.
 *
 * MESSAGING HOOK: when Batch 4 ships, add citadel_messages_destroy_pair()
 * here to hard-delete all messages between the two parties.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('conn_block', 30, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me       = (int) citadel_current_user_id();
$targetId = citadel_input_int('user_id');
$reason   = citadel_input_string('reason', null, 255);

if ($targetId === null || $targetId <= 0) {
    citadel_json_error('invalid_user', 'A valid user_id is required.', 400);
}
if ($targetId === $me) {
    citadel_json_error('cannot_block_self', 'You cannot block yourself.', 400);
}

$existing = citadel_rel_get($me, $targetId);

// Idempotent: already blocked → 200
if ($existing !== null && $existing['state'] === 'blocked') {
    citadel_json_ok(['state' => 'blocked', 'message' => 'Already blocked.']);
}

try {
    citadel_rel_set($me, $targetId, 'blocked', $me, $reason);

    // If they were connected, decrement both counters
    if ($existing !== null && $existing['state'] === 'connected') {
        db_query(
            'UPDATE user_stats SET connection_count = GREATEST(0, connection_count - 1) WHERE user_id = ?',
            [$me]
        );
        db_query(
            'UPDATE user_stats SET connection_count = GREATEST(0, connection_count - 1) WHERE user_id = ?',
            [$targetId]
        );
    }

    // TODO (Batch 4): citadel_messages_destroy_pair($me, $targetId);

    // Silent — no notification. The invisibility is the message.

    citadel_log('api', 'info', 'User blocked', [
        'blocker' => $me,
        'blocked' => $targetId,
        'had_state' => $existing['state'] ?? 'none',
    ]);

} catch (Throwable $e) {
    citadel_log('api', 'error', 'Block failed', [
        'blocker' => $me,
        'blocked' => $targetId,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('block_failed', 'Could not complete the operation.', 500);
}

citadel_json_ok([
    'state'   => 'blocked',
    'message' => 'User blocked. You will no longer see each other.',
]);