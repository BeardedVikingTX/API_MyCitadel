<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_send', CITADEL_MSG_MAX_PER_HOUR, 3600);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$convId = isset($body['conversation_id']) ? (int) $body['conversation_id'] : 0;
$to     = isset($body['to']) ? (int) $body['to'] : 0;

if ($convId <= 0 && $to <= 0) {
    citadel_json_error('invalid_target', 'Provide conversation_id or to.', 400);
}

if ($convId <= 0) {
    if (!citadel_msg_are_connected($me, $to)) {
        citadel_json_error('not_connected',
            'You must be connected to message this user.', 403);
    }
    try {
        $convId = citadel_msg_open_direct($me, $to);
    } catch (Throwable $e) {
        citadel_json_error('create_failed', 'Could not open conversation.', 500);
    }
}

if (!citadel_msg_is_participant($convId, $me)) {
    citadel_json_error('conversation_not_found', 'Conversation not found.', 404);
}

$bodyText = isset($body['body']) && is_string($body['body']) ? trim($body['body']) : '';

$tokens = [];
if (isset($body['attachment_tokens']) && is_array($body['attachment_tokens'])) {
    foreach (array_slice($body['attachment_tokens'], 0, CITADEL_MSG_MAX_ATTACHMENTS) as $t) {
        if (is_string($t) && preg_match('/^[a-f0-9]{32}$/', $t)) $tokens[] = $t;
    }
}

if ($bodyText === '' && empty($tokens)) {
    citadel_json_error('empty_message',
        'A message must have text or at least one attachment.', 400);
}
if (mb_strlen($bodyText) > CITADEL_MSG_MAX_CHARS) {
    citadel_json_error('message_too_long',
        'Messages are limited to ' . CITADEL_MSG_MAX_CHARS . ' characters.', 400);
}

$idem = null;
if (isset($body['idempotency_key']) && is_string($body['idempotency_key'])) {
    if (preg_match('/^[a-f0-9]{32}$/', $body['idempotency_key'])) {
        $idem = strtolower($body['idempotency_key']);
        $existing = db_one(
            'SELECT id FROM messages WHERE idempotency_key = ? LIMIT 1',
            [$idem]
        );
        if ($existing !== null) {
            citadel_json_ok([
                'message_id'      => (int) $existing['id'],
                'conversation_id' => $convId,
                'duplicate'       => true,
            ]);
        }
    }
}

try {
    $enc = citadel_msg_encrypt_body($bodyText, $convId);
} catch (Throwable $e) {
    citadel_log('security', 'error', 'Message encrypt failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('encrypt_failed', 'Could not encrypt message.', 500);
}

$db = db();
$db->beginTransaction();

try {
    db_query(
        'INSERT INTO messages
            (conversation_id, sender_id, body_ct, body_nonce, idempotency_key)
         VALUES (?, ?, ?, ?, ?)',
        [$convId, $me, $enc['ct'], $enc['nonce'], $idem]
    );
    $msgId = (int) db_last_id();

    // Bind attachments
    if (!empty($tokens)) {
        $ph = implode(',', array_fill(0, count($tokens), '?'));
        db_query(
            "UPDATE post_attachments
                SET message_id = ?
              WHERE served_token IN ($ph)
                AND user_id = ?
                AND post_id IS NULL
                AND comment_id IS NULL
                AND message_id IS NULL",
            array_merge([$msgId], $tokens, [$me])
        );
    }

    db_query(
        'UPDATE conversations SET last_message_at = UTC_TIMESTAMP() WHERE id = ?',
        [$convId]
    );

    // Sender auto-reads own message
    db_query(
        'UPDATE conversation_participants
            SET last_read_message_id = GREATEST(last_read_message_id, ?)
          WHERE conversation_id = ? AND user_id = ?',
        [$msgId, $convId, $me]
    );

    $db->commit();
} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    citadel_log('api', 'error', 'Message insert failed', [
        'user_id' => $me, 'error' => $e->getMessage(),
    ]);
    citadel_json_error('send_failed', 'Could not send message.', 500);
}

// Notify recipient
$otherId = citadel_msg_other_user($convId, $me);
if ($otherId !== null) {
    try {
        require_once CITADEL_CONFIG . '/notifications.php';
        citadel_notify(
            $otherId,
            'message_received',
            'New message',
            mb_substr($bodyText, 0, 80) ?: '[attachment]',
            $me,
            ['user_id' => $me, 'conversation_id' => $convId, 'message_id' => $msgId],
            '/messages?c=' . $convId
        );
    } catch (Throwable $e) {
        citadel_log('push', 'warning', 'Message notification failed', [
            'error' => $e->getMessage(),
        ]);
    }
}

citadel_json_ok([
    'message_id'      => $msgId,
    'conversation_id' => $convId,
], 201);