<?php
/* ============================================================================
 * ███ CONNECTIONS/LIST.PHP ███
 * MyCitadel — List Active Connections
 * ----------------------------------------------------------------------------
 * Route  : GET /v1/connections
 * Query  : ?limit=50&offset=0&sort=recent|rep|name
 * Auth   : Required
 * Rate   : 60 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT IT DOES
 * ────────────────────────────────────────────────────────────────────────────
 * Returns the list of users the current user is connected with.
 * Each entry includes enough data to render a connection card without
 * additional API calls.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * SORTING
 * ────────────────────────────────────────────────────────────────────────────
 *   recent (default) — most recently connected first
 *   rep              — highest reputation first
 *   name             — alphabetical by username
 *
 * ────────────────────────────────────────────────────────────────────────────
 * PRIVACY
 * ────────────────────────────────────────────────────────────────────────────
 *   • Only 'connected' state relationships are returned
 *   • Never includes blocked users (defensive — shouldn't be possible)
 *   • Never includes inactive/banned users
 *   • No encrypted PII in the response
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

// ── Pagination ────────────────────────────────────────────────────────────
$limit  = max(1, min(100, (int) ($_GET['limit']  ?? 50)));
$offset = max(0,          (int) ($_GET['offset'] ?? 0));

// ── Sort mode ─────────────────────────────────────────────────────────────
$sortRaw = isset($_GET['sort']) && is_string($_GET['sort']) ? $_GET['sort'] : 'recent';
$orderBy = match ($sortRaw) {
    'rep'   => 'reputation DESC, r.updated_at DESC',
    'name'  => 'u.username ASC',
    default => 'r.updated_at DESC',
};

// ── Query ─────────────────────────────────────────────────────────────────
// Note: the CASE expression identifies the OTHER user in each relationship.
// Since relationships are canonicalized (low_id < high_id), if 'me' is the
// low side, the other is the high side, and vice versa.
$rows = db_all(
    "SELECT
        u.id, u.username, u.created_at AS member_since, u.last_active_at,
        u.is_premium,
        p.display_name, p.tagline, p.avatar_url, p.avatar_frame_id,
        p.banner_url, p.accent_color, p.country_code, p.state_code,
        LEFT(COALESCE(p.bio, ''), 140) AS bio_preview,
        COALESCE(s.reputation_points, 0) AS reputation,
        COALESCE(s.badge_count, 0)       AS badge_count,
        COALESCE(s.post_count, 0)        AS post_count,
        r.updated_at AS connected_since
       FROM user_relationships r
       JOIN users u
         ON u.id = CASE
                     WHEN r.user_low_id = ? THEN r.user_high_id
                     ELSE r.user_low_id
                   END
       LEFT JOIN user_profiles p ON p.user_id = u.id
       LEFT JOIN user_stats    s ON s.user_id = u.id
      WHERE (r.user_low_id = ? OR r.user_high_id = ?)
        AND r.state = 'connected'
        AND u.is_active = 1
        AND u.is_banned = 0
      ORDER BY {$orderBy}
      LIMIT ? OFFSET ?",
    [$me, $me, $me, $limit, $offset]
);

// ── Total count for pagination UI ─────────────────────────────────────────
$total = (int) db_scalar(
    'SELECT COUNT(*)
       FROM user_relationships r
       JOIN users u
         ON u.id = CASE
                     WHEN r.user_low_id = ? THEN r.user_high_id
                     ELSE r.user_low_id
                   END
      WHERE (r.user_low_id = ? OR r.user_high_id = ?)
        AND r.state = "connected"
        AND u.is_active = 1
        AND u.is_banned = 0',
    [$me, $me, $me]
);

// ── Transform rows ────────────────────────────────────────────────────────
$connections = array_map(static function (array $r): array {
    return [
        'id'              => (int) $r['id'],
        'username'        => (string) $r['username'],
        'display_name'    => $r['display_name'],
        'tagline'         => $r['tagline'],
        'bio_preview'     => $r['bio_preview'] ?: null,
        'avatar_url'      => $r['avatar_url'],
        'avatar_frame_id' => $r['avatar_frame_id'] !== null
                                ? (int) $r['avatar_frame_id']
                                : null,
        'banner_url'      => $r['banner_url'],
        'accent_color'    => (string) $r['accent_color'],
        'country_code'    => $r['country_code'],
        'state_code'      => $r['state_code'],
        'reputation'      => (int) $r['reputation'],
        'badge_count'     => (int) $r['badge_count'],
        'post_count'      => (int) $r['post_count'],
        'is_premium'      => (bool) $r['is_premium'],
        'member_since'    => gmdate('c', strtotime((string) $r['member_since'])),
        'connected_since' => gmdate('c', strtotime((string) $r['connected_since'])),
        'last_active_at'  => $r['last_active_at']
                                ? gmdate('c', strtotime((string) $r['last_active_at']))
                                : null,
    ];
}, $rows);

// ── Response ──────────────────────────────────────────────────────────────
citadel_json_ok([
    'connections' => $connections,
    'total'       => $total,
    'limit'       => $limit,
    'offset'      => $offset,
    'sort'        => $sortRaw,
    'has_more'    => ($offset + count($connections)) < $total,
]);