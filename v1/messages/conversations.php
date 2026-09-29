<?php
declare(strict_types=1);
require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/messages.php';

citadel_rate_limit('msg_list', 120, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me    = (int) citadel_current_user_id();
$limit = isset($_GET['limit']) ? max(1, min(50, (int) $_GET['limit'])) : 30;

$rows = db_all(
    'SELECT c.id, c.last_message_at, p.last_read_message_id
       FROM conversations c
       JOIN conversation_participants p
         ON p.conversation_id = c.id AND p.user_id = ? AND p.left_at IS NULL
      WHERE c.is_archived = 0
      ORDER BY c.last_message_at DESC
      LIMIT ' . $limit,
    [$me]
);

$out = [];
foreach ($rows as $c) {
    $convId = (int) $c['id'];

    $otherId = citadel_msg_other_user($convId, $me);
    $otherUser = null;
    if ($otherId !== null) {
        $u = db_one(
            'SELECT u.id, u.username, p.display_name, p.avatar_url
               FROM users u
               LEFT JOIN user_profiles p ON p.user_id = u.id
              WHERE u.id = ? LIMIT 1',
            [$otherId]
        );
        if ($u !== null) {
            $otherUser = [
                'id'           => (int) $u['id'],
                'username'     => (string) $u['username'],
                'display_name' => $u['display_name'],
                'avatar_url'   => $u['avatar_url'],
            ];
        }
    }

    $last = db_one(
        'SELECT id, sender_id, body_ct, body_nonce, is_deleted, created_at
           FROM messages WHERE conversation_id = ?
          ORDER BY id DESC LIMIT 1',
        [$convId]
    );

    $preview = null;
    $lastSender = null;
    if ($last !== null) {
        $lastSender = (int) $last['sender_id'];
        if ((int) $last['is_deleted'] === 1) {
            $preview = '[deleted]';
        } else {
            $pt = citadel_msg_decrypt_body($last['body_ct'], $last['body_nonce'], $convId);
            $preview = $pt !== null ? mb_substr($pt, 0, 100) : '[encrypted]';
        }
    }

    $unread = (int) db_scalar(
        'SELECT COUNT(*) FROM messages
          WHERE conversation_id = ?
            AND sender_id != ?
            AND id > ?',
        [$convId, $me, (int) $c['last_read_message_id']]
    );

    $out[] = [
        'id'              => $convId,
        'other'           => $otherUser,
        'last_preview'    => $preview,
        'last_sender_id'  => $lastSender,
        'unread_count'    => $unread,
        'last_message_at' => $c['last_message_at']
            ? gmdate('c', strtotime((string) $c['last_message_at']))
            : null,
    ];
}

citadel_json_ok(['conversations' => $out]);