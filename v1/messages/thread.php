<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_thread', 60, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me     = (int) citadel_current_user_id();
$convId = isset($_GET['conversation_id']) ? (int) $_GET['conversation_id'] : 0;
$before = isset($_GET['before_id']) ? (int) $_GET['before_id'] : 0;
$limit  = isset($_GET['limit']) ? max(1, min(100, (int) $_GET['limit'])) : 50;

if ($convId <= 0) {
    citadel_json_error('invalid_conversation', 'conversation_id is required.', 400);
}

if (!citadel_msg_is_participant($convId, $me)) {
    citadel_json_error('conversation_not_found', 'Conversation not found.', 404);
}

$sql    = 'SELECT id, conversation_id, sender_id, body_ct, body_nonce,
                  is_deleted, edited_at, created_at
             FROM messages WHERE conversation_id = ?';
$params = [$convId];

if ($before > 0) {
    $sql .= ' AND id < ?';
    $params[] = $before;
}

$sql .= ' ORDER BY id DESC LIMIT ' . $limit;

$rows = db_all($sql, $params);
$rows = array_reverse($rows); // chronological order

$messages = array_map('citadel_msg_hydrate', $rows);

$other = citadel_msg_other_user($convId, $me);
$otherUser = null;
if ($other !== null) {
    $row = db_one(
        'SELECT u.id, u.username, p.display_name, p.avatar_url
           FROM users u
           LEFT JOIN user_profiles p ON p.user_id = u.id
          WHERE u.id = ? LIMIT 1',
        [$other]
    );
    if ($row !== null) {
        $otherUser = [
            'id'           => (int) $row['id'],
            'username'     => (string) $row['username'],
            'display_name' => $row['display_name'],
            'avatar_url'   => $row['avatar_url'],
        ];
    }
}

citadel_json_ok([
    'conversation_id' => $convId,
    'messages'        => $messages,
    'other'           => $otherUser,
    'has_more'        => count($messages) === $limit,
]);