<?php
/* ============================================================================
 * ███ NOTIFICATIONS/LIST.PHP ███
 * Route : GET /v1/notifications?unread_only=1&limit=50
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';

citadel_rate_limit('notif_list', 120, 60);
citadel_require_auth('json');

$me = (int) citadel_current_user_id();

$unreadOnly = isset($_GET['unread_only']) && $_GET['unread_only'] === '1';
$limit      = max(1, min(100, (int) ($_GET['limit'] ?? 50)));

$sql = 'SELECT n.id, n.type, n.title, n.body, n.payload, n.link,
               n.read_at, n.created_at, n.actor_id,
               a.username AS actor_username,
               p.display_name AS actor_display_name,
               p.avatar_url   AS actor_avatar_url
          FROM notifications n
          LEFT JOIN users a ON a.id = n.actor_id
          LEFT JOIN user_profiles p ON p.user_id = n.actor_id
         WHERE n.user_id = ?';

$params = [$me];

if ($unreadOnly) {
    $sql .= ' AND n.read_at IS NULL';
}

$sql .= ' ORDER BY n.created_at DESC LIMIT ?';
$params[] = $limit;

$rows = db_all($sql, $params);

$items = array_map(static function (array $r): array {
    return [
        'id'         => (int) $r['id'],
        'type'       => (string) $r['type'],
        'title'      => (string) $r['title'],
        'body'       => $r['body'],
        'payload'    => $r['payload'] !== null ? json_decode((string) $r['payload'], true) : null,
        'link'       => $r['link'],
        'read'       => $r['read_at'] !== null,
        'created_at' => gmdate('c', strtotime((string) $r['created_at'])),
        'actor'      => $r['actor_id'] !== null ? [
            'id'           => (int) $r['actor_id'],
            'username'     => (string) $r['actor_username'],
            'display_name' => $r['actor_display_name'],
            'avatar_url'   => $r['actor_avatar_url'],
        ] : null,
    ];
}, $rows);

$unreadCount = (int) db_scalar(
    'SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL',
    [$me]
);

citadel_json_ok([
    'notifications' => $items,
    'unread_count'  => $unreadCount,
]);