<?php
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
$msgId = isset($body['id']) ? (int) $body['id'] : 0;

if ($msgId <= 0) {
    citadel_json_error('invalid_id', 'Message id required.', 400);
}

$msg = db_one(
    'SELECT id, sender_id, conversation_id FROM messages WHERE id = ? LIMIT 1',
    [$msgId]
);

if ($msg === null || (int) $msg['sender_id'] !== $me) {
    // Silent 404 — don't reveal whether the message exists
    citadel_json_error('message_not_found', 'Message not found.', 404);
}

db_query(
    'UPDATE messages
        SET is_deleted = 1, body_ct = "", body_nonce = ""
      WHERE id = ?',
    [$msgId]
);

citadel_json_ok(['deleted' => true]);