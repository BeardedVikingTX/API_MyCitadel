<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_read', 120, 60);
citadel_require_csrf();
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    citadel_json_error('method_not_allowed', 'POST only.', 405);
}

$me   = (int) citadel_current_user_id();
$body = citadel_input_json();

$convId = isset($body['conversation_id']) ? (int) $body['conversation_id'] : 0;
$upto   = isset($body['up_to_message_id']) ? (int) $body['up_to_message_id'] : 0;

if ($convId <= 0 || $upto <= 0) {
    citadel_json_error('invalid_input', 'conversation_id and up_to_message_id required.', 400);
}

if (!citadel_msg_is_participant($convId, $me)) {
    citadel_json_error('conversation_not_found', 'Conversation not found.', 404);
}

db_query(
    'UPDATE conversation_participants
        SET last_read_message_id = GREATEST(last_read_message_id, ?)
      WHERE conversation_id = ? AND user_id = ?',
    [$upto, $convId, $me]
);

citadel_json_ok(['marked' => true]);