<?php
/* ============================================================================
 * ███ CONNECTIONS/PENDING.PHP ███
 * Route : GET /v1/connections/pending
 * Returns incoming requests awaiting MY response.
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('conn_pending', 60, 60);
citadel_require_auth('json');

$me = (int) citadel_current_user_id();

$rows = db_all(
    'SELECT
        u.id, u.username,
        p.display_name, p.avatar_url, p.accent_color,
        COALESCE(s.reputation_points, 0) AS reputation,
        r.created_at AS requested_at,
        r.reason     AS intro_message
       FROM user_relationships r
       JOIN users u
         ON u.id = r.initiated_by
       LEFT JOIN user_profiles p ON p.user_id = u.id
       LEFT JOIN user_stats    s ON s.user_id = u.id
      WHERE r.state = "pending"
        AND r.initiated_by != ?
        AND (r.user_low_id = ? OR r.user_high_id = ?)
        AND u.is_active = 1
        AND u.is_banned = 0
      ORDER BY r.created_at DESC',
    [$me, $me, $me]
);

$pending = array_map(static function (array $r): array {
    return [
        'id'            => (int) $r['id'],
        'username'      => (string) $r['username'],
        'display_name'  => $r['display_name'],
        'avatar_url'    => $r['avatar_url'],
        'accent_color'  => (string) $r['accent_color'],
        'reputation'    => (int) $r['reputation'],
        'requested_at'  => gmdate('c', strtotime((string) $r['requested_at'])),
        'intro_message' => $r['intro_message'],
    ];
}, $rows);

citadel_json_ok([
    'pending' => $pending,
    'total'   => count($pending),
]);