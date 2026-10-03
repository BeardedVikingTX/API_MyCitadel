<?php
/* ============================================================================
 * ███ MESSAGES/DELETE.PHP ███
 * Route : POST /v1/messages/delete
 * Body  : { "id": 5 }                   ← delete a single message (any tier)
 *         { "conversation_id": 5 }      ← delete whole conversation (premium)
 *
 * TIER LIMITS:
 *   Free    — can delete own messages only
 *   Premium — can also delete conversations they participate in
 *             (full destruction for all participants)
 * ========================================================================== */

declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_delete', 60, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

/* ══════════════════════════════════════════════════════════════════════
 * TIER LIMITS
 * ========================================================================== */
$isPremium = ((int) db_scalar(
    'SELECT is_premium FROM users WHERE id = ? LIMIT 1',
    [$me]
)) === 1;

$msgId  = isset($body['id'])              ? (int) $body['id']              : 0;
$convId = isset($body['conversation_id']) ? (int) $body['conversation_id'] : 0;

/* ══════════════════════════════════════════════════════════════════════
 * PATH A — DELETE A CONVERSATION (premium only)
 * ========================================================================== */
if ($convId > 0) {
    if (!$isPremium) {
        citadel_json_error('tier_limit_exceeded',
            'Deleting whole conversations is a Premium feature. ' .
                'Free users can delete their own messages individually.',
            403);
    }

    if (!citadel_msg_is_participant($convId, $me)) {
        citadel_json_error('conversation_not_found', 'Conversation not found.', 404);
    }

    $db = db();
    $db->beginTransaction();

    try {
        // Collect attachment paths for disk cleanup
        $attachmentPaths = db_all(
            'SELECT pa.stored_path
               FROM post_attachments pa
               JOIN messages m ON m.id = pa.message_id
              WHERE m.conversation_id = ?',
            [$convId]
        );

        // Delete message attachments join rows
        db_query(
            'DELETE FROM message_attachments
              WHERE message_id IN (SELECT id FROM messages WHERE conversation_id = ?)',
            [$convId]
        );

        // Delete attachment rows
        db_query(
            'DELETE pa FROM post_attachments pa
               JOIN messages m ON m.id = pa.message_id
              WHERE m.conversation_id = ?',
            [$convId]
        );

        // Delete all messages
        db_query('DELETE FROM messages WHERE conversation_id = ?', [$convId]);

        // Delete participants
        db_query('DELETE FROM conversation_participants WHERE conversation_id = ?', [$convId]);

        // Delete the conversation itself
        db_query('DELETE FROM conversations WHERE id = ?', [$convId]);

        $db->commit();

        // Purge files from disk (best-effort, after commit)
        foreach ($attachmentPaths as $row) {
            $path = (string) $row['stored_path'];
            if ($path !== '' && is_file($path)) @unlink($path);
        }

        citadel_log('api', 'info', 'Conversation destroyed by premium user', [
            'user_id'         => $me,
            'conversation_id' => $convId,
        ]);

        citadel_json_ok([
            'deleted' => true,
            'message' => 'Conversation destroyed for all participants.',
        ]);

    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        citadel_log('api', 'error', 'Conversation delete failed', [
            'user_id' => $me, 'conversation_id' => $convId, 'error' => $e->getMessage(),
        ]);
        citadel_json_error('delete_failed', 'Could not delete conversation.', 500);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * PATH B — DELETE A SINGLE MESSAGE (any tier)
 * ========================================================================== */
if ($msgId <= 0) {
    citadel_json_error('invalid_id', 'Provide id or conversation_id.', 400);
}

$msg = db_one(
    'SELECT id, sender_id, conversation_id FROM messages WHERE id = ? LIMIT 1',
    [$msgId]
);

if ($msg === null || (int) $msg['sender_id'] !== $me) {
    citadel_json_error('message_not_found', 'Message not found.', 404);
}

db_query(
    'UPDATE messages
        SET is_deleted = 1, body_ct = "", body_nonce = ""
      WHERE id = ?',
    [$msgId]
);

citadel_log('api', 'info', 'Message deleted', [
    'message_id' => $msgId,
    'user_id'    => $me,
    'tier'       => $isPremium ? 'premium' : 'free',
]);

citadel_json_ok(['deleted' => true]);