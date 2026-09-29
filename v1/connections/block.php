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
require_once CITADEL_CONFIG . '/messages.php';

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

        // ── Destroy every message between the two users ────────────────
        // Per the Terms of Service: severing a connection destroys the
        // entire conversation history. Not hidden, not archived, gone.
        //
        // The direct conversation between the pair, if it exists, is
        // removed entirely: messages, participants, and the conversation
        // row itself. Attachments bound to those messages are also
        // unlinked from the attachment table so they can be garbage
        // collected, and their files are deleted from disk.
        try {
            $convId = citadel_msg_find_direct($me, $targetId);

            if ($convId !== null) {
                // Collect attachment file paths BEFORE we delete the
                // message rows, so we can purge them from disk.
                $attachmentPaths = db_all(
                    'SELECT pa.stored_path
                       FROM post_attachments pa
                       JOIN message_attachments ma ON ma.attachment_id = pa.id
                       JOIN messages m ON m.id = ma.message_id
                      WHERE m.conversation_id = ?',
                    [$convId]
                );

                // Delete message attachments join rows
                db_query(
                    'DELETE ma FROM message_attachments ma
                       JOIN messages m ON m.id = ma.message_id
                      WHERE m.conversation_id = ?',
                    [$convId]
                );

                // Delete attachments themselves (rows + files)
                db_query(
                    'DELETE pa FROM post_attachments pa
                       JOIN messages m ON m.id = pa.message_id
                      WHERE m.conversation_id = ?',
                    [$convId]
                );

                // Delete messages
                db_query(
                    'DELETE FROM messages WHERE conversation_id = ?',
                    [$convId]
                );

                // Delete participants
                db_query(
                    'DELETE FROM conversation_participants WHERE conversation_id = ?',
                    [$convId]
                );

                // Delete the conversation itself
                db_query(
                    'DELETE FROM conversations WHERE id = ?',
                    [$convId]
                );

                // Purge files from disk — best-effort, after commit
                foreach ($attachmentPaths as $row) {
                    $path = (string) $row['stored_path'];
                    if ($path !== '' && is_file($path)) {
                        @unlink($path);
                    }
                }

                citadel_log('api', 'info', 'Conversation destroyed on sever', [
                    'by'              => $me,
                    'with'            => $targetId,
                    'conversation_id' => $convId,
                    'messages_purged' => true,
                ]);
            }
        } catch (Throwable $e) {
            // Message destruction failure must NOT roll back the block.
            // The block is the security-critical action; leftover
            // ciphertext is inert without the connection.
            citadel_log('api', 'error', 'Message destruction failed on sever', [
                'by'    => $me,
                'with'  => $targetId,
                'error' => $e->getMessage(),
            ]);
        }
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