<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_stream', 60, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me    = (int) citadel_current_user_id();
$since = isset($_GET['since']) ? max(0, (int) $_GET['since']) : 0;

// CRITICAL: release the session lock immediately. Otherwise any other
// request from this user (like sending a message) blocks until this
// endpoint returns.
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

$maxHold   = 25;
$pollEvery = 500000; // 500ms
$start     = time();

while ((time() - $start) < $maxHold) {
    $rows = db_all(
        'SELECT m.id, m.conversation_id, m.sender_id, m.body_ct, m.body_nonce,
                m.is_deleted, m.edited_at, m.created_at
           FROM messages m
           JOIN conversation_participants cp
             ON cp.conversation_id = m.conversation_id
            AND cp.user_id = ?
            AND cp.left_at IS NULL
          WHERE m.id > ?
          ORDER BY m.id ASC
          LIMIT 50',
        [$me, $since]
    );

    if (!empty($rows)) {
        $messages = array_map('citadel_msg_hydrate', $rows);
        $lastId = (int) end($rows)['id'];

        citadel_json_ok([
            'messages' => $messages,
            'last_id'  => $lastId,
        ]);
    }

    usleep($pollEvery);
}

// Timeout — no new messages
citadel_json_ok([
    'messages' => [],
    'last_id'  => $since,
    'timeout'  => true,
]);