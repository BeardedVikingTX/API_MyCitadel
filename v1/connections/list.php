<?php
/* ============================================================================
 * ███ CONNECTIONS/LIST.PHP ███
 * Route : GET /v1/connections
 * Query : ?limit=50&offset=0
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('conn_list', 60, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me = (int) citadel_current_user_id();

$limit  = max(1, min(100, (int) ($_GET['limit']  ?? 50)));
$offset = max(0,          (int) ($_GET['offset'] ?? 0));

$rows = db_all(
    'SELECT
        u.id, u.username, u.created_at,
        p.display_name, p.avatar_url, p.avatar_frame_id, p.accent_color,
        COALESCE(s.reputation_points, 0) AS reputation,
        COALESCE(s.badge_count, 0)       AS badge_count,
        r.updated_at AS connected_since
       FROM user_relationships r
       JOIN users u
         ON u.id = CASE WHEN r.user_low_id = ? THEN r.user_high_id ELSE r.user_low_id END
       LEFT JOIN user_profiles p ON p.user_id = u.id
       LEFT JOIN user_stats    s ON s.user_id = u.id
      WHERE (r.user_low_id = ? OR r.user_high_id = ?)
        AND r.state = "connected"
        AND u.is_active = 1
        AND u.is_banned = 0
      ORDER BY r.updated_at DESC
      LIMIT ? OFFSET ?',
    [$me, $me, $me, $limit, $offset]
);

$total = (int) db_scalar(
    'SELECT COUNT(*) FROM user_relationships
      WHERE (user_low_id = ? OR user_high_id = ?) AND state = "connected"',
    [$me, $me]
);

$connections = array_map(static function (array $r): array {
    return [
        'id'              => (int) $r['id'],
        'username'        => (string) $r['username'],
        'display_name'    => $r['display_name'],
        'avatar_url'      => $r['avatar_url'],
        'avatar_frame_id' => $r['avatar_frame_id'] !== null ? (int) $r['avatar_frame_id'] : null,
        'accent_color'    => (string) $r['accent_color'],
        'reputation'      => (int) $r['reputation'],
        'badge_count'     => (int) $r['badge_count'],
        'connected_since' => gmdate('c', strtotime((string) $r['connected_since'])),
    ];
}, $rows);

citadel_json_ok([
    'connections' => $connections,
    'total'       => $total,
    'limit'       => $limit,
    'offset'      => $offset,
]);