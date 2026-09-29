<?php
/* ============================================================================
 * ███ CONNECTIONS/BLOCK.PHP ███
 * MyCitadel — Block / Deny / Sever
 * ----------------------------------------------------------------------------
 * Route : POST /v1/connections/block
 * Body  : { "user_id": 5, "reason": "optional" }
 *
 * THREE CONTEXTS, ONE ENDPOINT:
 *
 *   1. DENY  (target sent me a pending request)
 *      → Silent to target's UI? No — notify them: "declined"
 *      → No reputation change (they never earned it)
 *
 *   2. CANCEL + BLOCK (I sent them a pending request, now blocking)
 *      → Silent (I'm withdrawing)
 *      → No reputation change
 *
 *   3. SEVER (we were connected, now blocked)
 *      → Silent (the invisibility is the message)
 *      → Deduct 25 reputation from BOTH users
 *      → [Batch 4+] Destroy all messages between the two parties
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';
require_once CITADEL_CONFIG . '/notifications.php';
require_once CITADEL_CONFIG . '/reputation.php';

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

// Validate target exists (fixes the 500-vs-404 issue)
$targetExists = db_scalar('SELECT 1 FROM users WHERE id = ? LIMIT 1', [$targetId]);
if ($targetExists === null) {
    citadel_json_error('user_not_found', 'User not found.', 404);
}

$db = citadel_db();

try {
    $db->beginTransaction();

    // ── Load current relationship with lock ────────────────────────────────
    [$low, $high] = citadel_pair($me, $targetId);

    $stmt = $db->prepare(
        'SELECT * FROM user_relationships
          WHERE user_low_id = ? AND user_high_id = ?
          FOR UPDATE'
    );
    $stmt->execute([$low, $high]);
    $rel = $stmt->fetch();

    // If already blocked → idempotent success
    if ($rel !== false && $rel['state'] === 'blocked') {
        $db->commit();
        citadel_json_ok([
            'state'   => 'blocked',
            'message' => 'Already blocked.',
        ]);
    }

    // ── Determine context ──────────────────────────────────────────────────
    $wasConnected = ($rel !== false && $rel['state'] === 'connected');
    $wasPending   = ($rel !== false && $rel['state'] === 'pending');
    $pendingFromMe= $wasPending && ((int) $rel['initiated_by'] === $me);
    $pendingToMe  = $wasPending && ((int) $rel['initiated_by'] !== $me);

    // ── Apply the block ────────────────────────────────────────────────────
    citadel_rel_set($me, $targetId, 'blocked', $me, $reason);

    // ── Reputation deduction if we were connected ──────────────────────────
    if ($wasConnected) {
        // Deduct the 25 they each earned on connection
        award_points(
            $me,
            'connection_severed',
            -25,
            'user',
            $targetId,
            'Connection severed'
        );
        award_points(
            $targetId,
            'connection_severed',
            -25,
            'user',
            $me,
            'Connection severed'
        );

        // Decrement connection counters
        db_query(
            'UPDATE user_stats SET connection_count = GREATEST(0, connection_count - 1) WHERE user_id = ?',
            [$me]
        );
        db_query(
            'UPDATE user_stats SET connection_count = GREATEST(0, connection_count - 1) WHERE user_id = ?',
            [$targetId]
        );

        // TODO (Batch 4): citadel_messages_destroy_pair($me, $targetId);
    }

    // ── Pending from them? Cancel without counter adjustment ───────────────
    if ($wasPending && $pendingFromMe) {
        // I'm cancelling my own request. No counter existed, no rep awarded.
        // Nothing extra to do.
    }

    // ── Consume the connection_request notification if we denied them ──────
    if ($wasPending && $pendingToMe) {
        // They requested us; we're denying. Remove the notification
        // from our own feed so it doesn't linger.
        db_query(
            "DELETE FROM notifications
              WHERE user_id = ?
                AND actor_id = ?
                AND type = 'connection_request'",
            [$me, $targetId]
        );
    }
    
    // ── Cancel case: clean up OUR OWN outgoing request notification ────────
    if ($wasPending && $pendingFromMe) {
        // We sent the request and now cancelling. The recipient's notification
        // (about our request) is now stale — remove it from their feed.
        db_query(
            "DELETE FROM notifications
              WHERE user_id = ?
                AND actor_id = ?
                AND type = 'connection_request'",
            [$targetId, $me]
        );
    }
    
    $db->commit();

} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Block failed', [
        'blocker' => $me,
        'blocked' => $targetId,
        'error'   => $e->getMessage(),
    ]);
    citadel_json_error('block_failed', 'Could not complete the operation.', 500);
}

// ── Notify the initiator ONLY if we denied THEIR request ──────────────────
// (Silent for sever and cancel — the invisibility is the message.)
if ($wasPending && $pendingToMe) {
    try {
        citadel_notify(
            $targetId,   // they initiated
            'connection_denied',
            'Connection request declined',
            'Your connection request was not accepted.',
            $me,
            ['user_id' => $me],
            null   // no link — the target is now hidden from them
        );
    } catch (Throwable $e) {
        citadel_log('api', 'warning', 'Deny notification failed', [
            'target_id' => $targetId,
            'error'     => $e->getMessage(),
        ]);
    }
}

citadel_log('api', 'info', 'Block applied', [
    'blocker'      => $me,
    'blocked'      => $targetId,
    'was_connected'=> $wasConnected,
    'was_pending'  => $wasPending,
]);

$message = $wasConnected
    ? 'Connection severed. All messages destroyed. Reputation adjusted.'
    : ($wasPending && $pendingToMe
        ? 'Request declined. You will no longer see each other.'
        : 'User blocked. You will no longer see each other.');

citadel_json_ok([
    'state'    => 'blocked',
    'severed'  => $wasConnected,
    'denied'   => ($wasPending && $pendingToMe),
    'message'  => $message,
]);