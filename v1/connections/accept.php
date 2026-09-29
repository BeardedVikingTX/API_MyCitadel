<?php
/* ============================================================================
 * ███ CONNECTIONS/ACCEPT.PHP ███
 * MyCitadel — Accept a Connection Request
 * ----------------------------------------------------------------------------
 * Route : POST /v1/connections/accept
 * Body  : { "user_id": 5 }
 *
 * Atomic: state transition uses a conditional UPDATE — no race window.
 * Awards: +25 reputation to BOTH users on successful accept.
 * Notifies: the original requester that they were accepted.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';
require_once CITADEL_CONFIG . '/notifications.php';
require_once CITADEL_CONFIG . '/reputation.php';

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
if ($targetId === $me) {
    citadel_json_error('cannot_accept_self', 'Invalid request.', 400);
}

$db = citadel_db();

try {
    $db->beginTransaction();

    // ── 1. Load the current relationship (locked via SELECT ... FOR UPDATE) ──
    [$low, $high] = citadel_pair($me, $targetId);

    $stmt = $db->prepare(
        'SELECT * FROM user_relationships
          WHERE user_low_id = ? AND user_high_id = ?
          FOR UPDATE'
    );
    $stmt->execute([$low, $high]);
    $rel = $stmt->fetch();

    if ($rel === false) {
        $db->rollBack();
        citadel_json_error('no_request', 'No pending request.', 404);
    }

    // If already connected → idempotent success
    if ($rel['state'] === 'connected') {
        $db->commit();
        citadel_json_ok([
            'state'   => 'connected',
            'message' => 'Already connected.',
        ]);
    }

    // Blocked → silent 404
    if ($rel['state'] === 'blocked') {
        $db->rollBack();
        citadel_json_error('user_not_found', 'User not found.', 404);
    }

    // Only the recipient can accept
    if ((int) $rel['initiated_by'] === $me) {
        $db->rollBack();
        citadel_json_error('cannot_accept_own',
            'You cannot accept your own request.', 403);
    }

    // ── 2. Atomic state transition ──────────────────────────────────────────
    // The WHERE state='pending' clause ensures only one caller succeeds.
    $stmt = $db->prepare(
        "UPDATE user_relationships
            SET state        = 'connected',
                updated_at   = UTC_TIMESTAMP()
          WHERE user_low_id  = ?
            AND user_high_id = ?
            AND state        = 'pending'"
    );
    $stmt->execute([$low, $high]);

    if ($stmt->rowCount() !== 1) {
        // Another request beat us — treat as success idempotently.
        $db->commit();
        citadel_json_ok([
            'state'   => 'connected',
            'message' => 'Connection established.',
        ]);
    }

    $initiatorId = (int) $rel['initiated_by'];

    // ── 3. Bump connection counters ─────────────────────────────────────────
    db_query(
        'UPDATE user_stats SET connection_count = connection_count + 1 WHERE user_id = ?',
        [$me]
    );
    db_query(
        'UPDATE user_stats SET connection_count = connection_count + 1 WHERE user_id = ?',
        [$initiatorId]
    );

    // ── 4. Award reputation to BOTH users ───────────────────────────────────
    award_points(
        $me,
        'connection_made',
        25,
        'user',
        $initiatorId,
        'New connection established'
    );
    award_points(
        $initiatorId,
        'connection_made',
        25,
        'user',
        $me,
        'New connection established'
    );
    // Consume the original connection_request notification — it served
    // its purpose; the request has been accepted.
    db_query(
        "DELETE FROM notifications
          WHERE user_id = ?
            AND actor_id = ?
            AND type = 'connection_request'",
        [$me, $initiatorId]
    );
    
    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Connection accept failed', [
        'me'    => $me,
        'other' => $targetId,
        'error' => $e->getMessage(),
    ]);
    citadel_json_error('accept_failed', 'Could not accept the request.', 500);
}

// ── 5. Notify the initiator (outside transaction — fire-and-forget) ────────
try {
    citadel_notify(
        $initiatorId,
        'connection_accepted',
        'Connection accepted',
        'Your connection request was accepted. You can now see each other\'s profiles and posts.',
        $me,
        ['user_id' => $me, 'reputation_earned' => 25],
        '/connections'
    );
} catch (Throwable $e) {
    citadel_log('api', 'warning', 'Accept notification failed', [
        'initiator_id' => $initiatorId,
        'error'        => $e->getMessage(),
    ]);
}

citadel_log('api', 'info', 'Connection accepted', [
    'by'   => $me,
    'with' => $initiatorId,
]);

citadel_json_ok([
    'state'             => 'connected',
    'reputation_earned' => 25,
    'message'           => 'Connection established. +25 reputation.',
]);