<?php
/* ============================================================================
 * ███ USERS/LIST.PHP ███
 * MyCitadel — User Directory
 * ----------------------------------------------------------------------------
 * Route  : GET /v1/users/list
 * Query  : ?q=<search>&limit=24&offset=0&exclude_connected=1
 * Auth   : Required
 * Rate   : 30 requests per minute per IP
 *
 * ────────────────────────────────────────────────────────────────────────────
 * FILTERS
 * ────────────────────────────────────────────────────────────────────────────
 *   q                  — substring search on username or display_name
 *                        (case-insensitive, escapes LIKE wildcards)
 *   exclude_connected  — omit users already connected with the viewer
 *   limit / offset     — pagination (limit capped at 50)
 *
 * ────────────────────────────────────────────────────────────────────────────
 * VISIBILITY
 * ────────────────────────────────────────────────────────────────────────────
 *   • Only visibility='public' users
 *   • Excludes banned / inactive users
 *   • Excludes users blocked by or blocking the viewer
 *   • Excludes the viewer themselves
 * ========================================================================== */

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';
require_once CITADEL_CONFIG . '/db.php';
require_once CITADEL_CONFIG . '/connections.php';

citadel_rate_limit('users_list', 30, 60);
citadel_require_auth('json');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    header('Allow: GET');
    citadel_json_error('method_not_allowed', 'GET only.', 405);
}

$me     = (int) citadel_current_user_id();
$limit  = max(1, min(50, (int) ($_GET['limit']  ?? 24)));
$offset = max(0,        (int) ($_GET['offset'] ?? 0));

$excludeConnected = isset($_GET['exclude_connected'])
    && $_GET['exclude_connected'] === '1';

// ── Optional search query ─────────────────────────────────────────────────
$q = null;
if (isset($_GET['q']) && is_string($_GET['q'])) {
    $q = trim(mb_substr($_GET['q'], 0, 64));
    if ($q === '') $q = null;
}

// ── Viewer's block list — users they should never see ─────────────────────
$blockedIds = citadel_rel_exclusion_ids($me);

// ── Build WHERE fragments once, reuse in both queries ─────────────────────
$whereParts = [
    'u.id != ?',
    'u.is_active = 1',
    'u.is_banned = 0',
    '(p.visibility IS NULL OR p.visibility = "public")',
];

// Base params order matters — must match ? order in the SQL below
// The SQL places the viewer id twice in the JOIN, then once in WHERE,
// so params start with [me, me, me]
$baseParams = [$me, $me, $me];

// Search filter
$searchSql    = '';
$searchParams = [];
if ($q !== null) {
    // Escape LIKE metacharacters so "50%" doesn't act as a wildcard
    $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';
    $searchSql = ' AND (u.username LIKE ? OR p.display_name LIKE ?)';
    $searchParams = [$like, $like];
}

// Blocked users filter
$blockedSql    = '';
$blockedParams = [];
if (!empty($blockedIds)) {
    $ph = implode(',', array_fill(0, count($blockedIds), '?'));
    $blockedSql = " AND u.id NOT IN ({$ph})";
    $blockedParams = $blockedIds;
}

// exclude_connected filter
$connectedSql = $excludeConnected
    ? ' AND (r.state IS NULL OR r.state != "connected")'
    : '';

$whereSql = ' WHERE ' . implode(' AND ', $whereParts)
          . $searchSql
          . $blockedSql
          . $connectedSql;

// ── Main query ────────────────────────────────────────────────────────────
$selectSql = '
    SELECT
        u.id, u.username, u.created_at,
        p.display_name, p.tagline, p.avatar_url, p.avatar_frame_id,
        p.banner_url, p.wallpaper_url, p.accent_color,
        p.country_code, p.state_code,
        COALESCE(s.reputation_points, 0) AS reputation,
        COALESCE(s.badge_count, 0)       AS badge_count,
        r.state         AS rel_state,
        r.initiated_by  AS rel_initiated_by
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_stats    s ON s.user_id = u.id
      LEFT JOIN user_relationships r
             ON (r.user_low_id  = LEAST(u.id, ?) AND r.user_high_id = GREATEST(u.id, ?))
';

// $limit is already sanitized int; safe to inline (avoids PDO LIMIT binding issue)
$limitSql = ' ORDER BY u.created_at DESC LIMIT ' . $limit
          . ' OFFSET ' . $offset;

$params = array_merge($baseParams, $searchParams, $blockedParams);

$rows = db_all($selectSql . $whereSql . $limitSql, $params);

// ── Transform ─────────────────────────────────────────────────────────────
$users = array_map(static function (array $row) use ($me): array {
    $state = 'none';
    if ($row['rel_state'] === 'connected') {
        $state = 'connected';
    } elseif ($row['rel_state'] === 'pending') {
        $state = ((int) $row['rel_initiated_by'] === $me) ? 'pending_out' : 'pending_in';
    } elseif ($row['rel_state'] === 'blocked') {
        $state = 'blocked';   // defensive — should be excluded by NOT IN
    }

    return [
        'id'              => (int) $row['id'],
        'username'        => (string) $row['username'],
        'display_name'    => $row['display_name'],
        'tagline'         => $row['tagline'],
        'avatar_url'      => $row['avatar_url'],
        'avatar_frame_id' => $row['avatar_frame_id'] !== null
                                ? (int) $row['avatar_frame_id']
                                : null,
        'banner_url'      => $row['banner_url'],
        'wallpaper_url'   => $row['wallpaper_url'],
        'accent_color'    => (string) $row['accent_color'],
        'country_code'    => $row['country_code'],
        'state_code'      => $row['state_code'],
        'reputation'      => (int) $row['reputation'],
        'badge_count'     => (int) $row['badge_count'],
        'member_since'    => gmdate('c', strtotime((string) $row['created_at'])),
        'connection_state'=> $state,
    ];
}, $rows);

// ── Count query (same filters, no LIMIT) ──────────────────────────────────
$countSql = '
    SELECT COUNT(*)
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_relationships r
             ON (r.user_low_id  = LEAST(u.id, ?) AND r.user_high_id = GREATEST(u.id, ?))
'
. $whereSql;

$countParams = array_merge($baseParams, $searchParams, $blockedParams);
$total = (int) db_scalar($countSql, $countParams);

// ── Response ──────────────────────────────────────────────────────────────
citadel_json_ok([
    'users'    => $users,
    'total'    => $total,
    'limit'    => $limit,
    'offset'   => $offset,
    'has_more' => ($offset + count($users)) < $total,
    'q'        => $q,   // echo back so the client knows the filter
]);